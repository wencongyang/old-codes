# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import os
import os.path
import re
import string
import threading
import fcntl
from struct import pack, unpack, calcsize

from xen.util.xpopen import xPopen3
import xen.util.auxbin
import xen.lowlevel.xc

from xen.xend import balloon, sxp, image
from xen.xend.XendError import XendError, VmError
from xen.xend.XendLogging import log
from xen.xend.XendConfig import XendConfig
from xen.xend.XendConstants import *
from xen.xend import XendNode
from xen.xend.xenstore.xsutil import ResumeDomain
from xen.remus import util

SIGNATURE = "LinuxGuestRecord"
COLO_SIGNATURE = "GuestColoRestore"
QEMU_SIGNATURE = "QemuDeviceModelRecord"
dm_batch = 512
XC_SAVE = "xc_save"
XC_RESTORE = "xc_restore"


sizeof_int = calcsize("i")
sizeof_unsigned_int = calcsize("I")
sizeof_unsigned_long = calcsize("L")


xc = xen.lowlevel.xc.xc()


def write_exact(fd, buf, errmsg):
    if os.write(fd, buf) != len(buf):
        raise XendError(errmsg)


def read_exact(fd, size, errmsg):
    buf  = '' 
    while size != 0: 
        readstr = os.read(fd, size)
        if not len(readstr):
            log.error("read_exact: EOF trying to read %d (buf='%s')" % \
                      (size, buf))
            raise XendError(errmsg)
        size = size - len(readstr)
        buf  = buf + readstr
    return buf


def insert_after(list, pred, value):
    for i,k in enumerate(list):
        if type(k) == type([]):
           if k[0] == pred:
              list.insert (i+1, value)
    return


def save(fd, dominfo, network, live, dst, checkpoint=False, node=-1,sock=None):
    from xen.xend import XendDomain

    try:
        if not os.path.isdir("/var/lib/xen"):
            os.makedirs("/var/lib/xen")
    except Exception, exn:
        log.exception("Can't create directory '/var/lib/xen'")
        raise XendError("Can't create directory '/var/lib/xen'")

    write_exact(fd, SIGNATURE, "could not write guest state file: signature")

    sxprep = dominfo.sxpr()

    if node > -1:
        insert_after(sxprep,'vcpus',['node', str(node)])

    for device_sxp in sxp.children(sxprep, 'device'):
        backend = sxp.child(device_sxp[1], 'backend')
        if backend == None:
            continue
        bkdominfo = XendDomain.instance().domain_lookup_nr(backend[1])
        if bkdominfo == None:
            raise XendError("Could not find backend: %s" % backend[1])
        if bkdominfo.getDomid() == XendDomain.DOM0_ID:
            # Skip for compatibility of checkpoint data format
            continue
        backend[1] = bkdominfo.getName()
        
    config = sxp.to_string(sxprep)

    domain_name = dominfo.getName()
    # Rename the domain temporarily, so that we don't get a name clash if this
    # domain is migrating (live or non-live) to the local host.  Doing such a
    # thing is useful for debugging.
    dominfo.setName('migrating-' + domain_name)

    try:
        dominfo.migrateDevices(network, dst, DEV_MIGRATE_STEP1, domain_name)

        write_exact(fd, pack("!i", len(config)),
                    "could not write guest state file: config len")
        write_exact(fd, config, "could not write guest state file: config")

        image_cfg = dominfo.info.get('image', {})
        hvm = dominfo.info.is_hvm()

        # xc_save takes three customization parameters: maxit, max_f, and
        # flags the last controls whether or not save is 'live', while the
        # first two further customize behaviour when 'live' save is
        # enabled. Passing "0" simply uses the defaults compiled into
        # libxenguest; see the comments and/or code in xc_linux_save() for
        # more information.
        cmd = [xen.util.auxbin.pathTo(XC_SAVE), str(fd),
               str(dominfo.getDomid()), "0", "0", 
               str(int(live) | (int(hvm) << 2)) ]
        log.debug("[xc_save]: %s", string.join(cmd))

        def saveInputHandler(line, tochild):
            log.debug("In saveInputHandler %s", line)
            if line == "suspend":
                log.debug("Suspending %d ...", dominfo.getDomid())
                dominfo.shutdown('suspend')
                dominfo.waitForSuspend()
            if line in ('suspend', 'suspended'):
                dominfo.migrateDevices(network, dst, DEV_MIGRATE_STEP2,
                                       domain_name)
                log.info("Domain %d suspended.", dominfo.getDomid())
                dominfo.migrateDevices(network, dst, DEV_MIGRATE_STEP3,
                                       domain_name)
                if hvm:
                    dominfo.image.saveDeviceModel()

            if line == "suspend":
                tochild.write("done\n")
                tochild.flush()
                log.debug('Written done')

        forkHelper(cmd, fd, saveInputHandler, False)

        # put qemu device model state
        if os.path.exists("/var/lib/xen/qemu-save.%d" % dominfo.getDomid()):
            write_exact(fd, QEMU_SIGNATURE, "could not write qemu signature")
            qemu_fd = os.open("/var/lib/xen/qemu-save.%d" % dominfo.getDomid(),
                              os.O_RDONLY)
            while True:
                buf = os.read(qemu_fd, dm_batch)
                if len(buf):
                    write_exact(fd, buf, "could not write device model state")
                else:
                    break
            os.close(qemu_fd)
            os.remove("/var/lib/xen/qemu-save.%d" % dominfo.getDomid())

        if checkpoint:
            dominfo.resumeDomain()
        else:
            if live and sock != None:
                try:
                    sock.shutdown(2)
                except:
                    pass
                sock.close()

            dominfo.destroy()
            dominfo.testDeviceComplete()
        try:
            dominfo.setName(domain_name, False)
        except VmError:
            # Ignore this.  The name conflict (hopefully) arises because we
            # are doing localhost migration; if we are doing a suspend of a
            # persistent VM, we need the rename, and don't expect the
            # conflict.  This needs more thought.
            pass

    except Exception, exn:
        log.exception("Save failed on domain %s (%s) - resuming.", domain_name,
                      dominfo.getDomid())
        dominfo.resumeDomain()
 
        try:
            dominfo.setName(domain_name)
        except:
            log.exception("Failed to reset the migrating domain's name")

        raise exn


def restore(xd, fd, dominfo = None, paused = False, relocating = False):
    try:
        if not os.path.isdir("/var/lib/xen"):
            os.makedirs("/var/lib/xen")
    except Exception, exn:
        log.exception("Can't create directory '/var/lib/xen'")
        raise XendError("Can't create directory '/var/lib/xen'")

    signature = read_exact(fd, len(SIGNATURE),
        "not a valid guest state file: signature read")
    if signature != SIGNATURE and signature != COLO_SIGNATURE:
        raise XendError("not a valid guest state file: found '%s'" %
                        signature)

    if signature == COLO_SIGNATURE:
        colo = True
    else:
        colo = False
    if colo:
        log.debug("use colo mode")

    l = read_exact(fd, sizeof_int,
                   "not a valid guest state file: config size read")
    vmconfig_size = unpack("!i", l)[0]
    vmconfig_buf = read_exact(fd, vmconfig_size,
        "not a valid guest state file: config read")

    p = sxp.Parser()
    p.input(vmconfig_buf)
    if not p.ready:
        raise XendError("not a valid guest state file: config parse")

    vmconfig = p.get_val()

    if not relocating:
        domconfig = XendConfig(sxp_obj = vmconfig)
        othervm = xd.domain_lookup_nr(domconfig["name_label"])
        if othervm is None or othervm.domid is None:
            othervm = xd.domain_lookup_nr(domconfig["uuid"])
        if othervm is not None and othervm.domid is not None: 
            raise VmError("Domain '%s' already exists with ID '%d'" % (domconfig["name_label"], othervm.domid))

    if dominfo:
        dominfo.resume()
    else:
        dominfo = xd.restore_(vmconfig)

    image_cfg = dominfo.info.get('image', {})
    is_hvm = dominfo.info.is_hvm()

    if is_hvm:
        nomigrate = dominfo.info['platform'].get('nomigrate', 0)
    else:
        nomigrate = dominfo.info['platform'].get('nomigrate')
        if nomigrate is None:
            nomigrate = 0
    if int(nomigrate) != 0:
        dominfo.destroy()
        raise XendError("cannot restore non-migratable domain")

    store_port   = dominfo.getStorePort()
    console_port = dominfo.getConsolePort()

    assert store_port
    assert console_port

    # if hvm, pass mem size to calculate the store_mfn
    if is_hvm:
        apic = int(dominfo.info['platform'].get('apic', 0))
        pae  = int(dominfo.info['platform'].get('pae',  0))
        log.info("restore hvm domain %d, apic=%d, pae=%d",
                 dominfo.domid, apic, pae)
    else:
        apic = 0
        pae  = 0

    try:
        restore_image = image.create(dominfo, dominfo.info)
        memory = restore_image.getRequiredAvailableMemory(
            dominfo.info['memory_dynamic_max'] / 1024)
        maxmem = restore_image.getRequiredAvailableMemory(
            dominfo.info['memory_static_max'] / 1024)
        shadow = restore_image.getRequiredShadowMemory(
            dominfo.info['shadow_memory'] * 1024,
            dominfo.info['memory_static_max'] / 1024)

        log.debug("restore:shadow=0x%x, _static_max=0x%x, _static_min=0x%x, ",
                  dominfo.info['shadow_memory'],
                  dominfo.info['memory_static_max'],
                  dominfo.info['memory_static_min'])

        # Round shadow up to a multiple of a MiB, as shadow_mem_control
        # takes MiB and we must not round down and end up under-providing.
        shadow = ((shadow + 1023) / 1024) * 1024

        # set memory limit
        xc.domain_setmaxmem(dominfo.getDomid(), maxmem)

        vtd_mem = 0
        info = xc.physinfo()
        if 'hvm_directio' in info['virt_caps']:
            # Reserve 1 page per MiB of RAM for separate VT-d page table.
            vtd_mem = 4 * (dominfo.info['memory_static_max'] / 1024 / 1024)
            # Round vtd_mem up to a multiple of a MiB.
            vtd_mem = ((vtd_mem + 1023) / 1024) * 1024

        balloon.free(memory + shadow + vtd_mem, dominfo)

        shadow_cur = xc.shadow_mem_control(dominfo.getDomid(), shadow / 1024)
        dominfo.info['shadow_memory'] = shadow_cur

        superpages = restore_image.superpages

        cmd = map(str, [xen.util.auxbin.pathTo(XC_RESTORE),
                        fd, dominfo.getDomid(),
                        store_port, console_port, int(is_hvm), pae, apic,
                        superpages, int(colo)])
        log.debug("[xc_restore]: %s", string.join(cmd))

        inputHandler = RestoreInputHandler()
        restoreHandler = RestoreHandler(fd, colo, dominfo, inputHandler,
                                         is_hvm, restore_image)

        forkHelper(cmd, fd, inputHandler.handler, not colo, restoreHandler)

        # We don't want to pass this fd to any other children -- we 
        # might need to recover the disk space that backs it.
        try:
            flags = fcntl.fcntl(fd, fcntl.F_GETFD)
            flags |= fcntl.FD_CLOEXEC
            fcntl.fcntl(fd, fcntl.F_SETFD, flags)
        except:
            pass

        if inputHandler.store_mfn is None:
            raise XendError('Could not read store MFN')

        if not is_hvm and handler.console_mfn is None:
            raise XendError('Could not read console MFN')

        if not colo:
            # In colo mode, the vm is resumed in xc_restore
            restoreHandler.resume(True, paused, None)
        else:
            util.runcmd("/etc/xen/scripts/network-colo slaver uninstall vif%d.0 eth0" % dominfo.getDomid());

        return dominfo
    except Exception, exn:
        dominfo.destroy()
        log.exception(exn)
        raise exn


class RestoreHandler:
    def __init__(self, fd, colo, dominfo, inputHandler, is_hvm, restore_image):
        self.fd = fd
        self.colo = colo
        self.firsttime = True
        self.inputHandler = inputHandler
        self.dominfo = dominfo
        self.is_hvm = is_hvm
        self.restore_image = restore_image
        self.store_port = dominfo.store_port
        self.console_port = dominfo.console_port
        log.debug("port: %s %s" % (self.store_port, self.console_port))

    def log(self, op, target, str):
        if op == "write":
            log.debug("write %s to %s" % (str, target))
        elif op == "read":
            log.debug("read %s from %s" % (str, target))

    def resume(self, finish, paused, child):
        log.debug("call resume...")
        fd = self.fd
        failover = False
        dominfo = self.dominfo
        handler = self.inputHandler
        restore_image = self.restore_image
        log.debug("call setCpuid")
        restore_image.setCpuid()
        log.debug("call completeRestore")
        dominfo.completeRestore(handler.store_mfn, handler.console_mfn,
                                self.firsttime)

        if self.colo and not finish:
            # notify master that checkpoint finishes
            self.log("write", "master", "finish")
            try:
                write_exact(fd, "finish", "failed to write finish done")
                buf = read_exact(fd, 6, "failed to read resume flag")
                if buf != "resume":
                    return False
                self.log("read", "master", "resume")
            except Exception, e:
                log.debug("failover")
                failover = True

        from xen.xend import XendDomain

        if self.firsttime:
            lock = True
            try:
                XendDomain.instance().domains_lock.release()
            except:
                lock = False

            try:
                dominfo.waitForDevices() # Wait for backends to set up
            finally:
                if lock:
                    XendDomain.instance().domains_lock.acquire()
            if not paused:
                dominfo.unpause()
        else:
            # colo
            xc.domain_resume(dominfo.domid, 2)
            log.debug("calling xc.domain_resume %d" % dominfo.domid)
            log.debug("calling ResumeDomain")
            ResumeDomain(dominfo.domid)

        if self.colo and not finish:
            if failover:
                self.log("write", "xc_restore", "failover")
                child.tochild.write("failover")
                child.tochild.flush()
            else:
                self.log("write", "xc_restore", "_resume_")
                child.tochild.write("_resume_")
                child.tochild.flush()

            log.debug("dom info port: %s %s" % (dominfo.store_port, dominfo.console_port))
            dominfo.store_port = self.store_port
            dominfo.console_port = self.console_port

            self.firsttime = False

class RestoreInputHandler:
    def __init__(self):
        self.store_mfn = None
        self.console_mfn = None


    def handler(self, line, child, restoreHandler):
        if line == "finish":
            # colo
            return restoreHandler.resume(False, False, child)

        m = re.match(r"^(store-mfn) (\d+)$", line)
        if m:
            self.store_mfn = int(m.group(2))
            return True

        m = re.match(r"^(console-mfn) (\d+)$", line)
        if m:
            self.console_mfn = int(m.group(2))
            return True

        return False


def forkHelper(cmd, fd, inputHandler, closeToChild, restoreHandler):
    child = xPopen3(cmd, True, -1, [fd])

    if closeToChild:
        child.tochild.close()

    thread = threading.Thread(target = slurp, args = (child.childerr,))
    thread.start()

    try:
        try:
            while 1:
                line = child.fromchild.readline()
                if line == "":
                    break
                else:
                    line = line.rstrip()
                    log.debug('%s', line)
                    inputHandler(line, child, restoreHandler)

        except IOError, exn:
            raise XendError('Error reading from child process for %s: %s' %
                            (cmd, exn))
    finally:
        child.fromchild.close()
        if not closeToChild:
            child.tochild.close()
        thread.join()
        child.childerr.close()
        status = child.wait()

    if status >> 8 == 127:
        raise XendError("%s failed: popen failed" % string.join(cmd))
    elif status != 0:
        raise XendError("%s failed" % string.join(cmd))


def slurp(infile):
    while 1:
        line = infile.readline()
        if line == "":
            break
        else:
            line = line.strip()
            m = re.match(r"^ERROR: (.*)", line)
            if m is None:
                log.info('%s', line)
            else:
                log.error('%s', m.group(1))
