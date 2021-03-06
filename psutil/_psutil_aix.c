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
#include <mntent.h>
#include <sys/ioctl.h>
#include <sys/tihdr.h>
#include <stropts.h>
#include <netinet/tcp_fsm.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <libperfstat.h>

#include "arch/aix/ifaddrs.h"
#include "arch/aix/net_connections.h"
#include "_psutil_aix.h"


#define TV2DOUBLE(t)   (((t).tv_nsec * 0.000000001) + (t).tv_sec)

/*
 * Read a file content and fills a C structure with it.
 */
int
psutil_file_to_struct(char *path, void *fstruct, size_t size) {
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
psutil_proc_basic_info(PyObject *self, PyObject *args) {
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
psutil_proc_name_and_args(PyObject *self, PyObject *args) {
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
 * Retrieves all threads used by process returning a list of tuples
 * including thread id, user time and system time.
 */
static PyObject *
psutil_proc_threads(PyObject *self, PyObject *args) {
    long pid;
    PyObject *py_retlist = PyList_New(0);
    PyObject *py_tuple = NULL;
    perfstat_thread_t *threadt = NULL;
    perfstat_id_t id;
    int i, rc, thread_count;

    if (py_retlist == NULL)
        return NULL;
    if (! PyArg_ParseTuple(args, "l", &pid))
        goto error;

    /* Get the count of threads */
    thread_count = perfstat_thread(NULL, NULL, sizeof(perfstat_thread_t), 0);
    if (thread_count <= 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    /* Allocate enough memory */
    threadt = (perfstat_thread_t *)calloc(thread_count,
        sizeof(perfstat_thread_t));
    if (threadt == NULL) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    strcpy(id.name, "");
    rc = perfstat_thread(&id, threadt, sizeof(perfstat_thread_t),
        thread_count);
    if (rc <= 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    for (i = 0; i < thread_count; i++) {
        if (threadt[i].pid != pid)
            continue;

        py_tuple = Py_BuildValue("Idd",
                                 threadt[i].tid,
                                 threadt[i].ucpu_time,
                                 threadt[i].scpu_time);
        if (py_tuple == NULL)
            goto error;
        if (PyList_Append(py_retlist, py_tuple))
            goto error;
        Py_DECREF(py_tuple);
    }
    free(threadt);
    return py_retlist;

error:
    Py_XDECREF(py_tuple);
    Py_DECREF(py_retlist);
    if (threadt != NULL)
        free(threadt);
    return NULL;
}


static PyObject *
psutil_proc_io_counters(PyObject *self, PyObject *args) {
    long pid;
    int rc;
    perfstat_process_t procinfo;
    perfstat_id_t id;
    if (! PyArg_ParseTuple(args, "l", &pid))
        return NULL;

    snprintf(id.name, sizeof(id.name), "%ld", pid);
    rc = perfstat_process(&id, &procinfo, sizeof(perfstat_process_t), 1);
    if (rc <= 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return Py_BuildValue("(KKKK)",
                         procinfo.inOps,
                         procinfo.outOps,
                         procinfo.inBytes,
                         procinfo.outBytes);
}


/*
 * Return process user and system CPU times as a Python tuple.
 */
static PyObject *
psutil_proc_cpu_times(PyObject *self, PyObject *args) {
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
psutil_proc_cred(PyObject *self, PyObject *args) {
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
psutil_users(PyObject *self, PyObject *args) {
    struct utmpx *ut;
    PyObject *ret_list = PyList_New(0);
    PyObject *tuple = NULL;
    PyObject *user_proc = NULL;

    if (ret_list == NULL)
        return NULL;

    setutxent();
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
    endutxent();

    return ret_list;

error:
    Py_XDECREF(tuple);
    Py_DECREF(ret_list);
    if (ut != NULL)
        endutent();
    return NULL;
}


/*
 * Return disk mounted partitions as a list of tuples including device,
 * mount point and filesystem type.
 */
static PyObject *
psutil_disk_partitions(PyObject *self, PyObject *args) {
    FILE *file = NULL;
    struct mntent * mt = NULL;
    PyObject *py_retlist = PyList_New(0);
    PyObject *py_tuple = NULL;

    if (py_retlist == NULL)
        return NULL;

    file = setmntent(MNTTAB, "rb");
    if (file == NULL) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    mt = getmntent(file);
    while (mt != NULL) {
        py_tuple = Py_BuildValue(
            "(ssss)",
            mt->mnt_fsname,   // device
            mt->mnt_dir,    // mount point
            mt->mnt_type,    // fs type
            mt->mnt_opts);  // options
        if (py_tuple == NULL)
            goto error;
        if (PyList_Append(py_retlist, py_tuple))
            goto error;
        Py_DECREF(py_tuple);
        mt = getmntent(file);
    }
    endmntent(file);
    return py_retlist;

error:
    Py_XDECREF(py_tuple);
    Py_DECREF(py_retlist);
    if (file != NULL)
        endmntent(file);
    return NULL;
}


/*
 * Return a list of tuples for network I/O statistics.
 */
static PyObject *
psutil_net_io_counters(PyObject *self, PyObject *args) {
    perfstat_netadapter_t *statp = NULL;
    int tot, i;
    perfstat_id_t first;

    PyObject *py_retdict = PyDict_New();
    PyObject *py_ifc_info = NULL;

    if (py_retdict == NULL)
        return NULL;

    /* check how many perfstat_netadapter_t structures are available */
    tot = perfstat_netadapter(NULL, NULL, sizeof(perfstat_netadapter_t), 0);
    if (tot == 0) {
        PyErr_SetString(PyExc_RuntimeError, "no net adapter found");
        goto error;
    }
    if (tot < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }
    statp = (perfstat_netadapter_t *)
        malloc(tot * sizeof(perfstat_netadapter_t));
    if (statp == NULL) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }
    strcpy(first.name, FIRST_NETINTERFACE);
    tot = perfstat_netadapter(&first, statp,
        sizeof(perfstat_netadapter_t), tot);
    if (tot < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    for (i = 0; i < tot; i++) {
        py_ifc_info = Py_BuildValue("(KKKKKKKK)",
            statp[i].tx_bytes,
            statp[i].rx_bytes,
            statp[i].tx_packets,
            statp[i].rx_packets,
            statp[i].tx_errors,
            statp[i].rx_errors,
            statp[i].tx_packets_dropped,
            statp[i].rx_packets_dropped
           );
        if (!py_ifc_info)
            goto error;
        if (PyDict_SetItemString(py_retdict, statp[i].name, py_ifc_info))
            goto error;
        Py_DECREF(py_ifc_info);
    }

    free(statp);
    return py_retdict;

error:
    if (statp != NULL)
        free(statp);
    Py_XDECREF(py_ifc_info);
    Py_DECREF(py_retdict);
    return NULL;
}


static PyObject*
psutil_net_if_stats(PyObject* self, PyObject* args) {
    char *nic_name;
    int sock = 0;
    int ret;
    int mtu;
    struct ifreq ifr;
    PyObject *py_is_up = NULL;
    PyObject *py_retlist = NULL;

    if (! PyArg_ParseTuple(args, "s", &nic_name))
        return NULL;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1)
        goto error;

    strncpy(ifr.ifr_name, nic_name, sizeof(ifr.ifr_name));

    // is up?
    ret = ioctl(sock, SIOCGIFFLAGS, &ifr);
    if (ret == -1)
        goto error;
    if ((ifr.ifr_flags & IFF_UP) != 0)
        py_is_up = Py_True;
    else
        py_is_up = Py_False;
    Py_INCREF(py_is_up);

    // MTU
    ret = ioctl(sock, SIOCGIFMTU, &ifr);
    if (ret == -1)
        goto error;
    mtu = ifr.ifr_mtu;

    close(sock);
    py_retlist = Py_BuildValue("[Oi]", py_is_up, mtu);
    if (!py_retlist)
        goto error;
    Py_DECREF(py_is_up);
    return py_retlist;

error:
    Py_XDECREF(py_is_up);
    if (sock != 0)
        close(sock);
    PyErr_SetFromErrno(PyExc_OSError);
    return NULL;
}

// a signaler for connections without an actual status
static int PSUTIL_CONN_NONE = 128;


static PyObject *
psutil_boot_time(PyObject *self, PyObject *args) {
    float boot_time = 0.0;
    struct utmpx *ut;

    setutxent();
    while (NULL != (ut = getutxent())) {
        if (ut->ut_type == BOOT_TIME) {
            boot_time = (float)ut->ut_tv.tv_sec;
            break;
        }
    }
    endutxent();
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
psutil_per_cpu_times(PyObject *self, PyObject *args) {
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
 * Return disk IO statistics.
 */
static PyObject *
psutil_disk_io_counters(PyObject *self, PyObject *args) {
    PyObject *py_retdict = PyDict_New();
    PyObject *py_disk_info = NULL;
    perfstat_disk_t *diskt = NULL;
    perfstat_id_t id;
    int i, rc, disk_count;

    if (py_retdict == NULL)
        return NULL;

    /* Get the count of disks */
    disk_count = perfstat_disk(NULL, NULL, sizeof(perfstat_disk_t), 0);
    if (disk_count <= 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    /* Allocate enough memory */
    diskt = (perfstat_disk_t *)calloc(disk_count,
        sizeof(perfstat_disk_t));
    if (diskt == NULL) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    strcpy(id.name, FIRST_DISK);
    rc = perfstat_disk(&id, diskt, sizeof(perfstat_disk_t),
        disk_count);
    if (rc <= 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        goto error;
    }

    for (i = 0; i < disk_count; i++) {
        py_disk_info = Py_BuildValue(
            "KKKKKK",
            diskt[i].__rxfers,
            diskt[i].xfers - diskt[i].__rxfers,
            diskt[i].rblks * diskt[i].bsize,
            diskt[i].wblks * diskt[i].bsize,
            diskt[i].rserv / 1000 / 1000,  // from nano to milli secs
            diskt[i].wserv / 1000 / 1000   // from nano to milli secs
        );
        if (py_disk_info == NULL)
            goto error;
        if (PyDict_SetItemString(py_retdict, diskt[i].name,
                                 py_disk_info))
            goto error;
        Py_DECREF(py_disk_info);
    }
    free(diskt);
    return py_retdict;

error:
    Py_XDECREF(py_disk_info);
    Py_DECREF(py_retdict);
    if (diskt != NULL)
        free(diskt);
    return NULL;
}


/*
 * Return virtual memory usage statistics.
 */
static PyObject *
psutil_virtual_mem(PyObject *self, PyObject *args) {
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
 * Return stats about swap memory.
 */
static PyObject *
psutil_swap_mem(PyObject *self, PyObject *args) {
    int rc;
    int pagesize = getpagesize();
    perfstat_memory_total_t memory;

    rc = perfstat_memory_total(NULL, &memory, sizeof(perfstat_memory_total_t), 1);
    if (rc <= 0){
        PyErr_SetFromErrno(PyExc_OSError);
        return NULL;
    }

    return Py_BuildValue("KKKK",
        (unsigned long long) memory.pgsp_total,
        (unsigned long long) memory.pgsp_free,
        (unsigned long long) memory.pgins * pagesize,
        (unsigned long long) memory.pgouts * pagesize
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
    {"proc_threads", psutil_proc_threads, METH_VARARGS,
     "Return process threads"},
    {"proc_io_counters", psutil_proc_io_counters, METH_VARARGS,
     "Get process I/O counters."},

    // --- system-related functions
    {"users", psutil_users, METH_VARARGS,
     "Return currently connected users."},
    {"disk_partitions", psutil_disk_partitions, METH_VARARGS,
     "Return disk partitions."},
    {"boot_time", psutil_boot_time, METH_VARARGS,
     "Return system boot time in seconds since the EPOCH."},
    {"per_cpu_times", psutil_per_cpu_times, METH_VARARGS,
     "Return system per-cpu times as a list of tuples"},
    {"disk_io_counters", psutil_disk_io_counters, METH_VARARGS,
     "Return a Python dict of tuples for disk I/O statistics."},
    {"virtual_mem", psutil_virtual_mem, METH_VARARGS,
     "Return system virtual memory usage statistics"},
    {"swap_mem", psutil_swap_mem, METH_VARARGS,
     "Return stats about swap memory, in bytes"},
    {"net_io_counters", psutil_net_io_counters, METH_VARARGS,
     "Return a Python dict of tuples for network I/O statistics."},
    {"net_connections", psutil_net_connections, METH_VARARGS,
     "Return system-wide connections"},
    {"net_if_stats", psutil_net_if_stats, METH_VARARGS,
     "Return NIC stats (isup, mtu)"},
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
