#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/socket.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_sched.h>
#include <net/if.h>
#include <libnetlink.h>

#define TCA_BUF_MAX (64*1024)
#define NEXT_ARG()							\
	do {								\
		argv++;							\
		if (--argc <= 0) {					\
			fprintf(stderr, "Command line is not complete." \
				" Try option \"help\"\n");		\
			return -1;					\
		}							\
	} while(0)

enum {
	TCA_COLO_UNSPEC,
	TCA_COLO_IDX,
	TCA_COLO_FLAGS,
	__TCA_COLO_MAX,
};

struct colo_idx {
	uint32_t this_idx;
	uint32_t other_idx;
};

/* flags */
#define IS_MASTER	(1 << 0)

void duparg(const char *key, const char *arg)
{
	fprintf(stderr, "Error: duplicate \"%s\": \"%s\" is the second value.\n", key, arg);
	exit(1);
}

void invarg(const char *msg, const char *arg)
{
	fprintf(stderr, "Error: argument \"%s\" is wrong: %s\n", arg, msg);
	exit(1);
}

static int usage(void)
{
	fprintf(stderr, "Usage: tc qdisc [ add | del | replace | change ] dev STRING\n");
	fprintf(stderr, "       [ handle QHANDLE ] [ root | parent CLASSID ]\n");
	fprintf(stderr, "       QDISC_KIND [ dev STRING ]\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Where:\n");
	fprintf(stderr, "QDISC_KIND := { master | slaver. }\n");
	return -1;
}

struct rtnl_handle rth;

int get_qdisc_handle(__u32 *h, const char *str)
{
	__u32 maj;
	char *p;

	maj = TC_H_UNSPEC;
	if (strcmp(str, "none") == 0)
		goto ok;
	maj = strtoul(str, &p, 16);
	if (p == str)
		return -1;
	maj <<= 16;
	if (*p != ':' && *p!=0)
		return -1;
ok:
	*h = maj;
	return 0;
}

int get_tc_classid(__u32 *h, const char *str)
{
	__u32 maj, min;
	char *p;

	maj = TC_H_ROOT;
	if (strcmp(str, "root") == 0)
		goto ok;
	maj = TC_H_UNSPEC;
	if (strcmp(str, "none") == 0)
		goto ok;
	maj = strtoul(str, &p, 16);
	if (p == str) {
		maj = 0;
		if (*p != ':')
			return -1;
	}
	if (*p == ':') {
		if (maj >= (1<<16))
			return -1;
		maj <<= 16;
		str = p+1;
		min = strtoul(str, &p, 16);
		if (*p != 0)
			return -1;
		if (min >= (1<<16))
			return -1;
		maj |= min;
	} else if (*p != 0)
		return -1;

ok:
	*h = maj;
	return 0;
}

uint32_t get_idx(const char *name)
{
	uint32_t idx;

	idx = if_nametoindex(name);
	if (!idx)
		fprintf(stderr, "Cannot find device \"%s\"\n", name);

	return idx;
}

int parse_opt(int argc, char **argv, struct nlmsghdr *n, int cmd, int this_idx)
{
	struct colo_idx idx;
	struct rtattr *tail;
	int is_master, is_slaver;
	uint32_t flags = 0;

	if (cmd != RTM_NEWQDISC)
		return 0;

	is_master = 0;
	is_slaver = 0;
	memset(&idx, 0, sizeof(idx));

	while (argc > 0) {
		if (strcmp(*argv, "dev") ==0) {
			NEXT_ARG();
			if (idx.other_idx)
				duparg(*argv, "dev");

			idx.other_idx = get_idx(*argv);
			if (!idx.other_idx)
				return -1;

			idx.this_idx = this_idx;
			if (idx.this_idx == idx.other_idx) {
				fprintf(stderr, "Cannot use the same device\n");
				return -1;
			}
		} else if (strcmp(*argv, "master") == 0) {
			if (is_master || is_slaver) {
				fprintf(stderr, "\"master\" conflicts with \"slaver\"\n");
				return -1;
			}

			is_master = 1;
		} else if (strcmp(*argv, "slaver") == 0) {
			if (is_master || is_slaver) {
				fprintf(stderr, "\"slaver\" conflicts with \"master\"\n");
				return -1;
			}

			is_slaver = 1;
		} else {
			fprintf(stderr, "unsupported option \"%s\"\n", *argv);
			return -1;
		}
		argc--;
		argv++;
	}

	if (!idx.other_idx) {
		fprintf(stderr, "missing option dev\n");
		return -1;
	}

	if (!is_master && !is_slaver) {
		fprintf(stderr, "missing option master or slaver\n");
		return -1;
	}

	if (is_master)
		flags |= IS_MASTER;

	tail = NLMSG_TAIL(n);
	addattr_l(n, 1024, TCA_OPTIONS, NULL, 0);
	addattr_l(n, 1024, TCA_COLO_IDX, &idx, sizeof(idx));
	addattr_l(n, 1024, TCA_COLO_FLAGS, &flags, sizeof(flags));
	tail->rta_len = (void *) NLMSG_TAIL(n) - (void *) tail;
	return 0;
}

int tc_qdisc_modify(int cmd, unsigned flags, int argc, char **argv)
{
	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buff[TCA_BUF_MAX];
	} req;
	char k[16];
	uint32_t handle, idx = 0;

	memset(&req, 0, sizeof(req));
	memset(k, 0, sizeof(k));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST|flags;
	req.n.nlmsg_type = cmd;
	req.t.tcm_family = AF_UNSPEC;

	while (argc > 0) {
		if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();
			if (req.t.tcm_ifindex)
				duparg("dev", *argv);

			idx = get_idx(*argv);
			if (!idx)
				return -1;
			req.t.tcm_ifindex = idx;
		} else if (strcmp(*argv, "handle") == 0) {
			NEXT_ARG();
			if (req.t.tcm_handle)
				duparg("handle", *argv);
			if (get_qdisc_handle(&handle, *argv))
				invarg(*argv, "invalid qdisc ID");
			req.t.tcm_handle = handle;
		} else if (strcmp(*argv, "root") == 0) {
			if (req.t.tcm_parent) {
				fprintf(stderr, "Error: \"root\" is duplicate parent ID\n");
				return -1;
			}
			req.t.tcm_parent = TC_H_ROOT;
		} else if (strcmp(*argv, "parent") == 0) {
			NEXT_ARG();
			if (req.t.tcm_parent)
				duparg("parent", *argv);
			if (get_tc_classid(&handle, *argv))
				invarg(*argv, "invalid parent ID");
			req.t.tcm_parent = handle;
		} else if (strcmp(*argv, "colo") == 0) {
			strncpy(k, *argv, sizeof(k) - 1);
			argc--;
			argv++;
			break;
		} else if (strcmp(*argv, "help") == 0){
			usage();
			return 0;
		} else {
			fprintf(stderr, "unsupported qdisc %s\n", *argv);
			return -1;
		}
		argc--;
		argv++;
	}

	if (!k[0]) {
		fprintf(stderr, "no qdisc is specified\n");
		return -1;
	}

	addattr_l(&req.n, sizeof(req), TCA_KIND, k, strlen(k)+1);
	if (parse_opt(argc, argv, &req.n, cmd, idx))
		return -1;

	if (rtnl_talk(&rth, &req.n, 0, 0, NULL, NULL, NULL) < 0)
		return -1;

	return 0;
}

int matches(const char *cmd, const char *pattern)
{
	int len = strlen(cmd);
	if (len > strlen(pattern))
		return -1;
	return memcmp(pattern, cmd, len);
}

int do_qdisc(int argc, char *argv[])
{
	if (matches(*argv, "add") == 0)
		return tc_qdisc_modify(RTM_NEWQDISC, NLM_F_EXCL|NLM_F_CREATE, argc-1, argv+1);
	if (matches(*argv, "change") == 0)
		return tc_qdisc_modify(RTM_NEWQDISC, 0, argc-1, argv+1);
	if (matches(*argv, "replace") == 0)
		return tc_qdisc_modify(RTM_NEWQDISC, NLM_F_CREATE|NLM_F_REPLACE, argc-1, argv+1);
	if (matches(*argv, "link") == 0)
		return tc_qdisc_modify(RTM_NEWQDISC, NLM_F_REPLACE, argc-1, argv+1);
	if (matches(*argv, "delete") == 0)
		return tc_qdisc_modify(RTM_DELQDISC, 0,  argc-1, argv+1);

	fprintf(stderr, "Command \"%s\" is unknown, try \"tc qdisc help\".\n", *argv);
	return -1;
}

int main(int argc, char *argv[])
{
	int ret;

	if (rtnl_open(&rth, 0) < 0) {
		fprintf(stderr, "Cannot open rtnetlink\n");
		exit(1);
	}

	if (matches(argv[1], "qdisc")) {
		usage();
		exit(1);
	}

	argc -= 2;
	argv += 2;

	if (argc < 1) {
		usage();
		exit(1);
	}

	ret = do_qdisc(argc, argv);

	rtnl_close(&rth);

	if (ret)
		return 1;

	return 0;
}
