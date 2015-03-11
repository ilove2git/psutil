// Useful resources:
// proc filesystem: http://www-01.ibm.com/support/knowledgecenter/ssw_aix_61/com.ibm.aix.files/proc.htm
// libperfstat:     http://www-01.ibm.com/support/knowledgecenter/ssw_aix_61/com.ibm.aix.files/libperfstat.h.htm


#include <Python.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/sysinfo.h>
#include <sys/procfs.h>
#include <sys/socket.h>
#include <sys/thread.h>
#include <fcntl.h>
#include <utmp.h>
#include <utmpx.h>
#include <sys/ioctl.h>
#include <sys/tihdr.h>
#include <stropts.h>
#include <netinet/tcp_fsm.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <libperfstat.h>

#include "_psutil_aix.h"


#define TV2DOUBLE(t)   (((t).tv_nsec * 0.000000001) + (t).tv_sec)

/*
 * Read a file content and fills a C structure with it.
 */
int
psutil_file_to_struct(char *path, void *fstruct, size_t size)
{
    int fd;
    size_t nbytes;
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
        return 0;
    }
    nbytes = read(fd, fstruct, size);
    if (nbytes <= 0) {
        close(fd);
        PyErr_SetFromErrno(PyExc_OSError);
        return 0;
    }
    if (nbytes != size) {
        close(fd);
        PyErr_SetString(PyExc_RuntimeError, "structure size mismatch");
        return 0;
    }
    close(fd);
    return nbytes;
}


/*
 * Return process ppid, rss, vms, ctime, nice, nthreads, status and tty
 * as a Python tuple.
 */
static PyObject *
psutil_proc_basic_info(PyObject *self, PyObject *args)
{
    int pid;
    char path[100];
    psinfo_t info;

    if (! PyArg_ParseTuple(args, "i", &pid))
        return NULL;
    sprintf(path, "/proc/%i/psinfo", pid);
    if (! psutil_file_to_struct(path, (void *)&info, sizeof(info)))
        return NULL;
    return Py_BuildValue("KKKdiiiK",
                         (unsigned long long) info.pr_ppid,         // parent pid
                         (unsigned long long) info.pr_rssize,       // rss
                         (unsigned long long) info.pr_size,         // vms
                         TV2DOUBLE(info.pr_start),                  // create time
                         (int) info.pr_lwp.pr_nice,                 // nice
                         (int) info.pr_nlwp,                        // no. of threads
                         (int) info.pr_lwp.pr_state,                // status code
                         (unsigned long long)info.pr_ttydev         // tty nr
                        );
}


/*
 * Return process name and args as a Python tuple.
 */
static PyObject *
psutil_proc_name_and_args(PyObject *self, PyObject *args)
{
    int pid;
    char path[100];
    psinfo_t info;

    if (! PyArg_ParseTuple(args, "i", &pid))
        return NULL;
    sprintf(path, "/proc/%i/psinfo", pid);
    if (! psutil_file_to_struct(path, (void *)&info, sizeof(info)))
        return NULL;
    return Py_BuildValue("s#s", info.pr_fname, PRFNSZ, info.pr_psargs);
}


/*
 * Return process user and system CPU times as a Python tuple.
 */
static PyObject *
psutil_proc_cpu_times(PyObject *self, PyObject *args)
{
    int pid;
    char path[100];
    pstatus_t info;

    if (! PyArg_ParseTuple(args, "i", &pid))
        return NULL;
    sprintf(path, "/proc/%i/status", pid);
    if (! psutil_file_to_struct(path, (void *)&info, sizeof(info)))
        return NULL;
    // results are more precise than os.times()
    return Py_BuildValue("dd",
                         TV2DOUBLE(info.pr_utime),
                         TV2DOUBLE(info.pr_stime));
}


/*
 * Return process uids/gids as a Python tuple.
 */
static PyObject *
psutil_proc_cred(PyObject *self, PyObject *args)
{
    int pid;
    char path[100];
    prcred_t info;

    if (! PyArg_ParseTuple(args, "i", &pid))
        return NULL;
    sprintf(path, "/proc/%i/cred", pid);
    if (! psutil_file_to_struct(path, (void *)&info, sizeof(info)))
        return NULL;
    return Py_BuildValue("iiiiii",
                         info.pr_ruid, info.pr_euid, info.pr_suid,
                         info.pr_rgid, info.pr_egid, info.pr_sgid);
}


/*
 * Return users currently connected on the system.
 */
static PyObject *
psutil_users(PyObject *self, PyObject *args)
{
    struct utmpx *ut;
    PyObject *ret_list = PyList_New(0);
    PyObject *tuple = NULL;
    PyObject *user_proc = NULL;

    if (ret_list == NULL)
        return NULL;

    while (NULL != (ut = getutxent())) {
        if (ut->ut_type == USER_PROCESS)
            user_proc = Py_True;
        else
            user_proc = Py_False;
        tuple = Py_BuildValue(
            "(sssfO)",
            ut->ut_user,              // username
            ut->ut_line,              // tty
            ut->ut_host,              // hostname
            (float)ut->ut_tv.tv_sec,  // tstamp
            user_proc);               // (bool) user process
        if (tuple == NULL)
            goto error;
        if (PyList_Append(ret_list, tuple))
            goto error;
        Py_DECREF(tuple);
    }
    endutent();

    return ret_list;

error:
    Py_XDECREF(tuple);
    Py_DECREF(ret_list);
    if (ut != NULL)
        endutent();
    return NULL;
}


// a signaler for connections without an actual status
static int PSUTIL_CONN_NONE = 128;


static PyObject *
psutil_boot_time(PyObject *self, PyObject *args)
{
    float boot_time = 0.0;
    struct utmpx *ut;

    while (NULL != (ut = getutxent())) {
        if (ut->ut_type == BOOT_TIME) {
            boot_time = (float)ut->ut_tv.tv_sec;
            break;
        }
    }
    endutent();
    if (boot_time != 0.0) {
        return Py_BuildValue("f", boot_time);
    }
    else {
        PyErr_SetString(PyExc_RuntimeError, "can't determine boot time");
        return NULL;
    }
}


/*
 * Return a Python list of tuple representing per-cpu times
 */
static PyObject *
psutil_per_cpu_times(PyObject *self, PyObject *args)
{
    int ncpu, rc, i;
    perfstat_cpu_t *cpu;
    perfstat_id_t id;
    PyObject *py_retlist = PyList_New(0);
    PyObject *py_cputime = NULL;

    if (py_retlist == NULL)
        return NULL;

    /* get the number of cpus in ncpu */
    ncpu = perfstat_cpu(NULL, NULL, sizeof(perfstat_cpu_t), 0);
    if (ncpu <= 0){
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    /* allocate enough memory to hold the ncpu structures */
    cpu = (perfstat_cpu_t *) malloc(ncpu * sizeof(perfstat_cpu_t));
    if (cpu == NULL) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    strcpy(id.name, "");
    rc = perfstat_cpu(&id, cpu, sizeof(perfstat_cpu_t), ncpu);

    if (rc <= 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    for (i = 0; i < ncpu; i++) {
        py_cputime = Py_BuildValue(
            "(dddd)",
            (double)cpu[i].user,
            (double)cpu[i].sys,
            (double)cpu[i].idle,
            (double)cpu[i].wait);
        if (!py_cputime)
            goto error;
        if (PyList_Append(py_retlist, py_cputime))
            goto error;
        Py_DECREF(py_cputime);
    }
    free(cpu);
    return py_retlist;

error:
    Py_XDECREF(py_cputime);
    Py_DECREF(py_retlist);
    free(cpu);
    return NULL;
}



/*
 * Return virtual memory usage statistics.
 */
static PyObject *
psutil_virtual_mem(PyObject *self, PyObject *args)
{
    int rc;
    perfstat_memory_total_t memory;

    rc = perfstat_memory_total(NULL, &memory, sizeof(perfstat_memory_total_t), 1);
    if (rc <= 0){
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return Py_BuildValue("KKKK",
        (unsigned long long) memory.real_total,
        (unsigned long long) memory.real_free,
        (unsigned long long) memory.real_pinned,
        (unsigned long long) memory.real_inuse
    );
}


/*
 * define the psutil C module methods and initialize the module.
 */
static PyMethodDef
PsutilMethods[] =
{
    // --- process-related functions
    {"proc_basic_info", psutil_proc_basic_info, METH_VARARGS,
     "Return process ppid, rss, vms, ctime, nice, nthreads, status and tty"},
    {"proc_name_and_args", psutil_proc_name_and_args, METH_VARARGS,
     "Return process name and args."},
    {"proc_cpu_times", psutil_proc_cpu_times, METH_VARARGS,
     "Return process user and system CPU times."},
    {"proc_cred", psutil_proc_cred, METH_VARARGS,
     "Return process uids/gids."},

    // --- system-related functions
    {"users", psutil_users, METH_VARARGS,
     "Return currently connected users."},
    {"boot_time", psutil_boot_time, METH_VARARGS,
     "Return system boot time in seconds since the EPOCH."},
    {"per_cpu_times", psutil_per_cpu_times, METH_VARARGS,
     "Return system per-cpu times as a list of tuples"},
    {"virtual_mem", psutil_virtual_mem, METH_VARARGS,
     "Return system virtual memory usage statistics"},
{NULL, NULL, 0, NULL}
};


struct module_state {
    PyObject *error;
};

#if PY_MAJOR_VERSION >= 3
#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))
#else
#define GETSTATE(m) (&_state)
#endif

#if PY_MAJOR_VERSION >= 3

static int
psutil_aix_traverse(PyObject *m, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int
psutil_aix_clear(PyObject *m) {
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "psutil_aix",
    NULL,
    sizeof(struct module_state),
    PsutilMethods,
    NULL,
    psutil_aix_traverse,
    psutil_aix_clear,
    NULL
};

#define INITERROR return NULL

PyMODINIT_FUNC PyInit__psutil_aix(void)

#else
#define INITERROR return

void init_psutil_aix(void)
#endif
{
#if PY_MAJOR_VERSION >= 3
    PyObject *module = PyModule_Create(&moduledef);
#else
    PyObject *module = Py_InitModule("_psutil_aix", PsutilMethods);
#endif
    PyModule_AddIntConstant(module, "version", PSUTIL_VERSION);

    PyModule_AddIntConstant(module, "SIDL", TSIDL);
    PyModule_AddIntConstant(module, "SRUN", TSRUN);
    PyModule_AddIntConstant(module, "SSLEEP", TSSLEEP);
    PyModule_AddIntConstant(module, "SSWAP", TSSWAP);
    PyModule_AddIntConstant(module, "SSTOP", TSSTOP);
    PyModule_AddIntConstant(module, "SZOMB", TSZOMB);

    PyModule_AddIntConstant(module, "TCPS_CLOSED", TCPS_CLOSED);
    PyModule_AddIntConstant(module, "TCPS_CLOSING", TCPS_CLOSING);
    PyModule_AddIntConstant(module, "TCPS_CLOSE_WAIT", TCPS_CLOSE_WAIT);
    PyModule_AddIntConstant(module, "TCPS_LISTEN", TCPS_LISTEN);
    PyModule_AddIntConstant(module, "TCPS_ESTABLISHED", TCPS_ESTABLISHED);
    PyModule_AddIntConstant(module, "TCPS_SYN_SENT", TCPS_SYN_SENT);
    PyModule_AddIntConstant(module, "TCPS_SYN_RCVD", TCPS_SYN_RECEIVED);
    PyModule_AddIntConstant(module, "TCPS_FIN_WAIT_1", TCPS_FIN_WAIT_1);
    PyModule_AddIntConstant(module, "TCPS_FIN_WAIT_2", TCPS_FIN_WAIT_2);
    PyModule_AddIntConstant(module, "TCPS_LAST_ACK", TCPS_LAST_ACK);
    PyModule_AddIntConstant(module, "TCPS_TIME_WAIT", TCPS_TIME_WAIT);
    PyModule_AddIntConstant(module, "PSUTIL_CONN_NONE", PSUTIL_CONN_NONE);

    if (module == NULL)
        INITERROR;
#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}
