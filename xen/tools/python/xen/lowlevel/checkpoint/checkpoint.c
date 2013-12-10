/* python bridge to checkpointing API */

#include <Python.h>
#include <sys/wait.h>

#include <xs.h>
#include <xenctrl.h>
#include <xc_save_restore_colo.h>

#include "checkpoint.h"

#define PKG "xen.lowlevel.checkpoint"

#define COMP_IOC_MAGIC    'k'
#define COMP_IOCTWAIT     _IO(COMP_IOC_MAGIC, 0)
#define COMP_IOCTFLUSH    _IO(COMP_IOC_MAGIC, 1)
#define COMP_IOCTRESUME   _IO(COMP_IOC_MAGIC, 2)
#define NR_vif_block   313

static PyObject* CheckpointError;

typedef struct {
  PyObject_HEAD
  checkpoint_state cps;

  /* milliseconds between checkpoints */
  unsigned int interval;
  int armed;

  PyObject* suspend_cb;
  PyObject* postcopy_cb;
  PyObject* checkpoint_cb;
  PyObject* setup_cb;
  PyObject* check_cb;

  PyThreadState* threadstate;
  int colo;
  int first_time;
  int dev_fd;
  int dirtypg;
} CheckpointObject;

static int suspend_trampoline(void* data);
static int postcopy_trampoline(void* data);
static int checkpoint_trampoline(void* data);
static int post_sendstate_trampoline(void *data);

static PyObject* Checkpoint_new(PyTypeObject* type, PyObject* args,
                               PyObject* kwargs)
{
  CheckpointObject* self = (CheckpointObject*)type->tp_alloc(type, 0);

  if (!self)
    return NULL;

  checkpoint_init(&self->cps);
  self->suspend_cb = NULL;
  self->armed = 0;

  return (PyObject*)self;
}

static int Checkpoint_init(PyObject* obj, PyObject* args, PyObject* kwargs)
{
  return 0;
}

static void Checkpoint_dealloc(CheckpointObject* self)
{
  checkpoint_close(&self->cps);

  self->ob_type->tp_free((PyObject*)self);
}

static PyObject* pycheckpoint_open(PyObject* obj, PyObject* args)
{
  CheckpointObject* self = (CheckpointObject*)obj;
  checkpoint_state* cps = &self->cps;
  unsigned int domid;

  if (!PyArg_ParseTuple(args, "I", &domid))
    return NULL;

  if (checkpoint_open(cps, domid) < 0) {
    PyErr_SetString(CheckpointError, checkpoint_error(cps));

    return NULL;
  }

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* pycheckpoint_close(PyObject* obj, PyObject* args)
{
  CheckpointObject* self = (CheckpointObject*)obj;

  checkpoint_close(&self->cps);

  Py_XDECREF(self->suspend_cb);
  self->suspend_cb = NULL;
  Py_XDECREF(self->postcopy_cb);
  self->postcopy_cb = NULL;
  Py_XDECREF(self->checkpoint_cb);
  self->checkpoint_cb = NULL;
  Py_XDECREF(self->setup_cb);
  self->setup_cb = NULL;
  Py_XDECREF(self->check_cb);
  self->check_cb = NULL;

  Py_INCREF(Py_None);
  return Py_None;
}

static PyObject* pycheckpoint_start(PyObject* obj, PyObject* args) {
  CheckpointObject* self = (CheckpointObject*)obj;

  PyObject* iofile;
  PyObject* suspend_cb = NULL;
  PyObject* postcopy_cb = NULL;
  PyObject* checkpoint_cb = NULL;
  PyObject* setup_cb = NULL;
  PyObject* check_cb = NULL;
  unsigned int interval = 0;

  int fd;
  struct save_callbacks callbacks;
  int rc;
  int flags = 0;

  if (!PyArg_ParseTuple(args, "O|OOOOOII", &iofile, &suspend_cb, &postcopy_cb,
                       &checkpoint_cb, &setup_cb, &check_cb, &interval, &flags))
    return NULL;

  self->interval = interval;

  Py_INCREF(iofile);
  Py_XINCREF(suspend_cb);
  Py_XINCREF(postcopy_cb);
  Py_XINCREF(checkpoint_cb);
  Py_XINCREF(setup_cb);
  Py_XINCREF(check_cb);

  fd = PyObject_AsFileDescriptor(iofile);
  Py_DECREF(iofile);
  if (fd < 0) {
    PyErr_SetString(PyExc_TypeError, "invalid file handle");
    return NULL;
  }

  if (suspend_cb && suspend_cb != Py_None) {
    if (!PyCallable_Check(suspend_cb)) {
      PyErr_SetString(PyExc_TypeError, "suspend callback not callable");
      goto err;
    }
    self->suspend_cb = suspend_cb;
  } else
    self->suspend_cb = NULL;

  if (postcopy_cb && postcopy_cb != Py_None) {
    if (!PyCallable_Check(postcopy_cb)) {
      PyErr_SetString(PyExc_TypeError, "postcopy callback not callable");
      return NULL;
    }
    self->postcopy_cb = postcopy_cb;
  } else
    self->postcopy_cb = NULL;

  if (checkpoint_cb && checkpoint_cb != Py_None) {
    if (!PyCallable_Check(checkpoint_cb)) {
      PyErr_SetString(PyExc_TypeError, "checkpoint callback not callable");
      return NULL;
    }
    self->checkpoint_cb = checkpoint_cb;
  } else
    self->checkpoint_cb = NULL;

  if (setup_cb && setup_cb != Py_None) {
    if (!PyCallable_Check(setup_cb)) {
      PyErr_SetString(PyExc_TypeError, "setup callback not callable");
      return NULL;
    }
    self->setup_cb = setup_cb;
  } else
    self->setup_cb = NULL;

  if (flags & CHECKPOINT_FLAGS_COLO)
    self->colo = 1;
  else
    self->colo = 0;
  self->first_time = 1;
  self->dirtypg = 0;

  if (check_cb && check_cb != Py_None) {
    if (!PyCallable_Check(check_cb)) {
      PyErr_SetString(PyExc_TypeError, "check callback not callable");
      return NULL;
    }
    self->check_cb = check_cb;
  } else
    self->check_cb = NULL;

  callbacks.suspend = suspend_trampoline;
  callbacks.postcopy = postcopy_trampoline;
  callbacks.checkpoint = checkpoint_trampoline;
  callbacks.post_sendstate = post_sendstate_trampoline;
  callbacks.data = self;

  self->threadstate = PyEval_SaveThread();
  rc = checkpoint_start(&self->cps, fd, &callbacks);
  PyEval_RestoreThread(self->threadstate);

  if (rc < 0) {
    PyErr_SetString(CheckpointError, checkpoint_error(&self->cps));
    goto err;
  }

  Py_INCREF(Py_None);
  return Py_None;

  err:
  self->suspend_cb = NULL;
  Py_XDECREF(suspend_cb);
  self->postcopy_cb = NULL;
  Py_XDECREF(postcopy_cb);
  self->checkpoint_cb = NULL;
  Py_XDECREF(checkpoint_cb);
  self->setup_cb = NULL;
  Py_XDECREF(self->setup_cb);
  self->check_cb = NULL;
  Py_XDECREF(check_cb);

  return NULL;
}

static PyMethodDef Checkpoint_methods[] = {
  { "open", pycheckpoint_open, METH_VARARGS,
    "open connection to xen" },
  { "close", pycheckpoint_close, METH_NOARGS,
    "close connection to xen" },
  { "start", pycheckpoint_start, METH_VARARGS | METH_KEYWORDS,
    "begin a checkpoint" },
  { NULL, NULL, 0, NULL }
};

static PyTypeObject CheckpointType = {
  PyObject_HEAD_INIT(NULL)
  0,                          /* ob_size           */
  PKG ".checkpointer",   /* tp_name           */
  sizeof(CheckpointObject),   /* tp_basicsize      */
  0,                          /* tp_itemsize       */
  (destructor)Checkpoint_dealloc, /* tp_dealloc        */
  NULL,                       /* tp_print          */
  NULL,                       /* tp_getattr        */
  NULL,                       /* tp_setattr        */
  NULL,                       /* tp_compare        */
  NULL,                       /* tp_repr           */
  NULL,                       /* tp_as_number      */
  NULL,                       /* tp_as_sequence    */
  NULL,                       /* tp_as_mapping     */
  NULL,                       /* tp_hash           */
  NULL,                       /* tp_call           */
  NULL,                       /* tp_str            */
  NULL,                       /* tp_getattro       */
  NULL,                       /* tp_setattro       */
  NULL,                       /* tp_as_buffer      */
  Py_TPFLAGS_DEFAULT,         /* tp_flags          */
  "Checkpoint object",        /* tp_doc            */
  NULL,                       /* tp_traverse       */
  NULL,                       /* tp_clear          */
  NULL,                       /* tp_richcompare    */
  0,                          /* tp_weaklistoffset */
  NULL,                       /* tp_iter           */
  NULL,                       /* tp_iternext       */
  Checkpoint_methods,         /* tp_methods        */
  NULL,                       /* tp_members        */
  NULL,                       /* tp_getset         */
  NULL,                       /* tp_base           */
  NULL,                       /* tp_dict           */
  NULL,                       /* tp_descr_get      */
  NULL,                       /* tp_descr_set      */
  0,                          /* tp_dictoffset     */
  (initproc)Checkpoint_init,  /* tp_init           */
  NULL,                       /* tp_alloc          */
  Checkpoint_new,             /* tp_new            */
};

static PyMethodDef methods[] = {
  { NULL }
};

static char doc[] = "checkpoint API";

PyMODINIT_FUNC initcheckpoint(void) {
  PyObject *m;

  if (PyType_Ready(&CheckpointType) < 0)
    return;

  m = Py_InitModule3(PKG, methods, doc);

  if (!m)
    return;

  Py_INCREF(&CheckpointType);
  PyModule_AddObject(m, "checkpointer", (PyObject*)&CheckpointType);

  CheckpointError = PyErr_NewException(PKG ".error", NULL, NULL);
  Py_INCREF(CheckpointError);
  PyModule_AddObject(m, "error", CheckpointError);

  block_timer();
}

/* colo functions */

/* master                   slaver          comment
 * "continue"   ===>
 *              <===        "suspend"       guest is suspended
 */
static int notify_slaver_suspend(CheckpointObject *self)
{
    int fd = self->cps.fd;

    if (self->first_time == 1)
        return 0;

    colo_output_log(stderr, "nofity slaver suspend\n");
    return write_exact(fd, "continue", 8);
}

static int wait_slaver_suspend(CheckpointObject *self)
{
    int fd = self->cps.fd;
    xc_interface *xch = self->cps.xch;
    char buf[8];

    if (self->first_time == 1)
        return 0;

    if ( read_exact(fd, buf, 7) < 0) {
        PERROR("read: suspend");
        return -1;
    }

    buf[7] = '\0';
    if (strcmp(buf, "suspend")) {
        PERROR("read \"%s\", expect \"suspend\"", buf);
        return -1;
    }
    colo_output_log(stderr, "read suspend from slaver\n");

    return 0;
}

static int notify_slaver_start_checkpoint(CheckpointObject *self)
{
    int fd = self->cps.fd;
    xc_interface *xch = self->cps.xch;

    if (self->first_time == 1)
        return 0;

    colo_output_log(stderr, "notify slaver to start new checkpoint\n");
    if ( write_exact(fd, "start", 5) < 0) {
        PERROR("write start");
        return -1;
    }

    return 0;
}

/*
 * master                       slaver
 *                  <====       "finish"
 * flush packets
 * "resume"         ====>
 * resume vm                    resume vm
 *                  <====       "resume"
 */
static int notify_slaver_resume(CheckpointObject *self)
{
    int fd = self->cps.fd;
    xc_interface *xch = self->cps.xch;
    char buf[7];

    colo_output_log(stderr, "wait slaver to finish updating memory\n");
    /* wait slaver to finish update memory, device state... */
    if ( read_exact(fd, buf, 6) < 0) {
        PERROR("read: finish");
        return -1;
    }

    buf[6] = '\0';
    if (strcmp(buf, "finish")) {
        ERROR("read \"%s\", expect \"finish\"", buf);
        return -1;
    }
    colo_output_log(stderr, "read finish from slaver\n");

    if (!self->first_time) {
        colo_output_log(stderr, "flush packets\n");
        /* flush queued packets now */
        ioctl(self->dev_fd, COMP_IOCTFLUSH);
    }

    colo_output_log(stderr, "notify slaver to resume VM\n");
    /* notify slaver to resume vm*/
    if (write_exact(fd, "resume", 6) < 0) {
        PERROR("write: resume");
        return -1;
    }

    return 0;
}

static int install_fw_network(CheckpointObject *self)
{
    int rc;
    PyObject* result;

    PyEval_RestoreThread(self->threadstate);
    result = PyObject_CallFunction(self->setup_cb, NULL);
    self->threadstate = PyEval_SaveThread();

    if (!result)
        return -1;

    if (result == Py_None || PyObject_IsTrue(result))
        rc = 0;
    else
        rc = -1;

    Py_DECREF(result);

    return rc;
}

static int wait_slaver_resume(CheckpointObject *self)
{
    int fd = self->cps.fd;
    xc_interface *xch = self->cps.xch;
    char buf[7];

    colo_output_log(stderr, "wait slaver to resume vm\n");
    if (read_exact(fd, buf, 6) < 0) {
        PERROR("read resume");
        return -1;
    }

    buf[6] = '\0';
    if (strcmp(buf, "resume")) {
        ERROR("read \"%s\", expect \"resume\"", buf);
        return -1;
    }
    colo_output_log(stderr, "read resume from slaver\n");

    return 0;
}

static int colo_postresume(CheckpointObject *self)
{
    int rc;
    int dev_fd = self->dev_fd;

    rc = wait_slaver_resume(self);
    if (rc < 0)
        return rc;

    if (self->first_time) {
        colo_output_log(stderr, "install network\n");
        rc = install_fw_network(self);
        if (rc < 0) {
            colo_output_log(stderr, "install network fails\n");
            return rc;
        }
    } else {
        colo_output_log(stderr, "notify compare module to resume\n");
        ioctl(dev_fd, COMP_IOCTRESUME);
        syscall(NR_vif_block, 0);
    }

    return 0;
}

static int pre_checkpoint(CheckpointObject *self)
{
    xc_interface *xch = self->cps.xch;

    self->dev_fd = open("/dev/HA_compare", O_RDWR);
    if (self->dev_fd < 0) {
        PERROR("opening /dev/HA_compare fails");
        return -1;
    }

    return 0;
}

static void wait_new_checkpoint(CheckpointObject *self)
{
    int dev_fd = self->dev_fd;
    int err, saved_errno;
    PyObject* result;

    self->dirtypg = 0;
    while (1) {
        err = ioctl(dev_fd, COMP_IOCTWAIT);
        if (err == 0)
            break;

        if (err == -1) {
            if (errno != ETIME && errno != ERESTART) {
                colo_output_log(stderr, "ioctl() returns -1, errno: %d\n", errno);
                break;
            }
            saved_errno = errno;
        }

        if (!self->check_cb)
            continue;

        PyEval_RestoreThread(self->threadstate);
        result = PyObject_CallFunction(self->check_cb, NULL);
        self->threadstate = PyEval_SaveThread();

        if (!result)
            continue;

        if (result == Py_None || PyObject_IsTrue(result)) {
            Py_DECREF(result);
            break;
        }

        Py_DECREF(result);

#define periodically_dirtypg 1
        if (err == -1 && saved_errno == ETIME && periodically_dirtypg) {
          self->dirtypg = 1;
          return;
        }
    }

    syscall(NR_vif_block, 1);
}

/* private functions */

/* bounce C suspend call into python equivalent.
 * returns 1 on success or 0 on failure */
static int suspend_trampoline(void* data)
{
  CheckpointObject* self = (CheckpointObject*)data;

  PyObject* result;

  if (self->colo) {
    if (notify_slaver_suspend(self) < 0) {
      colo_output_log(stderr, "nofitying slaver suspend fails\n");
      return 0;
    }
  }

  /* call default suspend function, then python hook if available */
  if (self->armed) {
    if (checkpoint_wait(&self->cps) < 0) {
      fprintf(stderr, "%s\n", checkpoint_error(&self->cps));
      return 0;
    }
  } else {
    if (self->interval) {
      self->armed = 1;
      checkpoint_settimer(&self->cps, self->interval);
    }

    if (!checkpoint_suspend(&self->cps)) {
      fprintf(stderr, "%s\n", checkpoint_error(&self->cps));
      return 0;
    }
  }

  /* suspend_cb() should be called after both sides are suspended */
  if (self->colo) {
    if (wait_slaver_suspend(self) < 0) {
      colo_output_log(stderr, "waiting slaver suspend fails\n");
      return 0;
    }
  }

  if (!self->suspend_cb)
    goto start_checkpoint;

  PyEval_RestoreThread(self->threadstate);
  result = PyObject_CallFunction(self->suspend_cb, NULL);
  self->threadstate = PyEval_SaveThread();

  if (!result)
    return 0;

  if (result == Py_None || PyObject_IsTrue(result)) {
    Py_DECREF(result);
    goto start_checkpoint;
  }

  Py_DECREF(result);

  return 0;

start_checkpoint:
  if (self->colo) {
    if (notify_slaver_start_checkpoint(self) < 0) {
      colo_output_log(stderr, "nofitying slaver to start checkpoint fails\n");
      return 0;
    }

    /* PVM is suspended first when doing live migration,
     * and then it is suspended for a new checkpoint.
     */
    if (self->first_time == 1)
        /* live migration */
        self->first_time = 2;
    else if (self->first_time == 2)
        /* the first checkpoint */
        self->first_time = 0;
  }

  return 1;
}

static int postcopy_trampoline(void* data)
{
  CheckpointObject* self = (CheckpointObject*)data;

  PyObject* result;
  int rc = 0;

  /* send qemu state before writing other data to fd */
  colo_output_log(stderr, "call postflush to send qemu\n");
  if (checkpoint_postflush(&self->cps) < 0) {
      fprintf(stderr, "%s\n", checkpoint_error(&self->cps));
      return 0;
  }

  if (self->colo) {
    if (notify_slaver_resume(self) < 0) {
      colo_output_log(stderr, "nofitying slaver resume fails\n");
      return 0;
    }
  }

  if (!self->postcopy_cb)
    goto resume;

  PyEval_RestoreThread(self->threadstate);
  result = PyObject_CallFunction(self->postcopy_cb, NULL);

  if (result && (result == Py_None || PyObject_IsTrue(result)))
    rc = 1;

  Py_XDECREF(result);
  self->threadstate = PyEval_SaveThread();

  resume:
  if (checkpoint_resume(&self->cps) < 0) {
    fprintf(stderr, "%s\n", checkpoint_error(&self->cps));
    return 0;
  }

  if (self->colo) {
    if (colo_postresume(self) < 0) {
      colo_output_log(stderr, "postresume fails\n");
      return 0;
    }
  }

  return rc;
}

static int checkpoint_trampoline(void* data)
{
  CheckpointObject* self = (CheckpointObject*)data;

  PyObject* result;

  if (self->dirtypg)
    goto wait_checkpoint;

  if (self->colo && self->first_time) {
    if (pre_checkpoint(self) < 0) {
      colo_output_log(stderr, "pre_checkpoint() fails\n");
      return -1;
    }
  }

  if (!self->checkpoint_cb)
    goto wait_checkpoint;

  PyEval_RestoreThread(self->threadstate);
  result = PyObject_CallFunction(self->checkpoint_cb, NULL);
  self->threadstate = PyEval_SaveThread();

  if (!result)
    return 0;

  if (result == Py_None || PyObject_IsTrue(result)) {
    Py_DECREF(result);
    goto wait_checkpoint;
  }

  Py_DECREF(result);

  return 0;

wait_checkpoint:
  if (self->colo) {
    wait_new_checkpoint(self);
  }

  if (self->dirtypg) {
    /* when checkpoint, we send "continue" which len = 8, */
    if (write_exact(self->cps.fd, "dirtypg_", 8) < 0) {
      colo_output_log(stderr, "writing dirtypg fails\n");
      return -1;
    }
    return 2;
  }

  fprintf(stderr, "\n\n");
  colo_output_log(stderr, "new checkpoint..........\n");

  return 1;
}

static int post_sendstate_trampoline(void* data)
{
  CheckpointObject *self = data;
  int fd = self->cps.fd;
  int i = XC_SAVE_ID_LAST_CHECKPOINT;

  if (!self->colo)
    return 0;

  /* In colo mode, guest is running on slaver side, so we should
   * send XC_SAVE_ID_LAST_CHECKPOINT to slaver.
   */
  colo_output_log(stderr, "writing XC_SAVE_ID_LAST_CHECKPOINT to slaver\n");
  if (write_exact(fd, &i, sizeof(int)) < 0) {
    colo_output_log(stderr, "writing XC_SAVE_ID_LAST_CHECKPOINT fails\n");
    return -1;
  }

  return 0;
}
