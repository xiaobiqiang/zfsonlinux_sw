#!/usr/bin/python

import sys
import time
import getopt
import copy
import os

from decimal import Decimal
from signal import signal, SIGINT, SIGWINCH, SIG_DFL

g_cols = {
    # HDR:        [Size, Scale, Description]
    "nread":      [10, 1024, "number of bytes read per second"],
    "nwritten":   [10, 1024, "number of bytes written per second"],
    "reads":      [6, 1000, "number of read operations per second"],
    "writes":     [6, 1000, "number of write operations per second"],
    "wtime":      [6, 1000, "average number of wait transactions waiting"],
    "wlentime":   [10, 1000, "total number of wait transactions waiting"],
    "wupdate":    [10, 1000, "last time wait queue changed"],
    "rtime":      [6, 1000, "average number of run transactions waiting"],
    "rlentime":   [10, 1000, "total number of run transactions waiting"],
    "rupdate":    [10, 1000, "last time run queue changed"],
    "wcnt":       [6, 1000, "count of elements in run state"],
    "rcnt":       [6, 1000, "count of elements in wait state"],
    "name":       [10, 1000, "device name"], 
}

g_hdr = ["nread", "nwritten", "reads", "writes", "wtime", "wlentime",
       "wupdate", "rtime", "rlentime", "rupdate", "wcnt", "rcnt", "name"]
       
g_cmd = ("Usage: iostat.py [-hvlta] [-f fields] [-o file] [-s string] [interval [count]]\n") 
      
g_interval = 1           # Default interval is 1 second
g_count = 1              # Default count is 1
g_hdr_intr = 20          # Print header every 20 lines of output
g_sep = "  "             # Default separator is 2 spaces
g_output_filename = None
g_output_filehandle = None

g_lflag = False
g_tflag = False
g_aflag = False

#save the latest informations and stats
g_lun_name = {}
g_lun_stats = {}
g_tgt_name = {}
g_tgt_stats = {}

#save the stats which used to output
g_lun_stats_out = {}
g_tgt_stats_out = {}

def detailed_usage():
    sys.stderr.write("%s\n" % g_cmd)
    sys.stderr.write("Field definitions are as follows:\n")
    for key in g_cols:
        sys.stderr.write("%11s : %s\n" % (key, g_cols[key][2]))
    sys.stderr.write("\n")
    sys.exit(1)


def usage():
    sys.stderr.write("%s\n" % g_cmd)
    sys.stderr.write("\t -h : Print this help message\n")
    sys.stderr.write("\t -v : List all possible field headers and definitions\n")
    sys.stderr.write("\t -l : List lun stats\n")
    sys.stderr.write("\t -t : List target stats\n")
    sys.stderr.write("\t -a : List all stats\n")
    sys.stderr.write("\t -f : Specify specific fields to print (see -v)\n")
    sys.stderr.write("\t -o : Redirect output to the specified file\n")
    sys.stderr.write("\t -s : Override default field separator with custom character or string\n")
    sys.stderr.write("\nExamples:\n")
    sys.stderr.write("\tiostat.py -v\n")
    sys.stderr.write("\tiostat.py -l 1\n")
    sys.stderr.write("\tiostat.py -t 1\n")
    sys.stderr.write("\tiostat.py -a 1 10\n")
    sys.stderr.write("\tiostat.py -f nread,nwritten,reads,writes,name 1\n")
    sys.stderr.write("\tiostat.py -o /tmp/a.log 2 10\n")
    sys.stderr.write("\tiostat.py -s \",\" -o /tmp/a.log 2 10\n")
    sys.stderr.write("\n")
    sys.exit(1)

        
def kstat_get_lun_name(uid):
    k = [line.strip() for line in open("/proc/spl/kstat/stmf/" + "stmf_lu_" + uid)]
    if not k:
        sys.exit(1)        
    del k[0:2]
    namedic = {}
    for s in k:
        if not s:
            continue
        name, type, data = s.split()
        if (name.strip().find("lun-guid") >= 0) and (len(name.strip()) == len("lun-guid")):
            namedic["lun-guid"] = data.strip()
        elif (name.strip().find("lun-alias") >= 0) and (len(name.strip()) == len("lun-alias")):
            namedic["lun-alias"] = data.strip()
    return namedic
        
def kstat_get_tgt_name(uid):
    k = [line.strip() for line in open("/proc/spl/kstat/stmf/" + "stmf_tgt_" + uid)]
    if not k:
        sys.exit(1)        
    del k[0:2]    
    namedic = {}
    for s in k:
        if not s:
            continue
        name, type, data = s.split()
        if (name.strip().find("target-name") >= 0) and (len(name.strip()) == len("target-name")):
            namedic["target-name"] = data.strip()
        elif (name.strip().find("target-alias") >= 0) and (len(name.strip()) == len("target-alias")):
            namedic["target-alias"] = data.strip()
        elif (name.strip().find("protocol") >= 0) and (len(name.strip()) == len("protocol")):
            namedic["protocol"] = data.strip()
    return namedic
    

def kstat_get_lun_stats(uid):
    k = [line.strip() for line in open("/proc/spl/kstat/stmf/" + "stmf_lu_io_" + uid)]
    if not k:
        sys.exit(1)
        
    del k[0:2]    
    for s in k:
        if not s:
            continue
        nread,nwritten,reads,writes,wtime,wlentime,wupdate,rtime,rlentime,rupdate,wcnt,rcnt = s.split()
        return {"nread":Decimal(nread), "nwritten":Decimal(nwritten), "reads":Decimal(reads),
                "writes":Decimal(writes), "wtime":Decimal(wtime), "wlentime":Decimal(wlentime),
                "wupdate":Decimal(wupdate), "rtime":Decimal(rtime), "rlentime":Decimal(rlentime),
                "rupdate":Decimal(rupdate), "wcnt":Decimal(wcnt), "rcnt":Decimal(rcnt)}
        

def kstat_get_tgt_stats(uid):
    k = [line.strip() for line in open("/proc/spl/kstat/stmf/" + "stmf_tgt_io_" + uid)]
    if not k:
        sys.exit(1)
        
    del k[0:2]    
    for s in k:
        if not s:
            continue
        nread,nwritten,reads,writes,wtime,wlentime,wupdate,rtime,rlentime,rupdate,wcnt,rcnt = s.split()
        return {"nread":Decimal(nread), "nwritten":Decimal(nwritten), "reads":Decimal(reads),
                "writes":Decimal(writes), "wtime":Decimal(wtime), "wlentime":Decimal(wlentime),
                "wupdate":Decimal(wupdate), "rtime":Decimal(rtime), "rlentime":Decimal(rlentime),
                "rupdate":Decimal(rupdate), "wcnt":Decimal(wcnt), "rcnt":Decimal(rcnt)}

  
def kstat_update_luns():
    global g_lun_name
    global g_lun_stats

    g_lun_name = {}
    g_lun_stats = {}

    for root,dirs,files in os.walk("/proc/spl/kstat/stmf"):pass
    for file in files:
        #example: stmf_lu_io_fffffc17c6651ae8
        preflen=len("stmf_lu_io_")
        ret = file.find("stmf_lu_io_", 0, preflen)
        if ret < 0:
            continue
        uid = file[preflen:]
        g_lun_name[uid] = kstat_get_lun_name(uid)
        g_lun_stats[uid] = kstat_get_lun_stats(uid)

        
def kstat_update_tgts():
    global g_tgt_name
    global g_tgt_stats

    g_tgt_name = {}
    g_tgt_stats = {}
        
    for root,dirs,files in os.walk("/proc/spl/kstat/stmf"):pass
    for file in files:
        #example: stmf_tgt_io_fffffc07f55cd3a0
        preflen=len("stmf_tgt_io_")
        ret = file.find("stmf_tgt_io_", 0, preflen)
        if ret < 0:
            continue
        uid = file[preflen:]
        g_tgt_name[uid] = kstat_get_tgt_name(uid)
        g_tgt_stats[uid] = kstat_get_tgt_stats(uid)


def calculate_lun_stats():
    global g_lun_stats_out

    prev_lun_stats = copy.deepcopy(g_lun_stats)    
    kstat_update_luns()    
    g_lun_stats_out = {}   
    
    for key in g_lun_stats:
        dic = {}
        if key in prev_lun_stats:
            for d in prev_lun_stats[key]:
                dic[d] = (g_lun_stats[key][d] - prev_lun_stats[key][d]) / g_interval
        else:
            for d in g_lun_stats[key]:
                dic[d] = g_lun_stats[key][d] / g_interval
        g_lun_stats_out[key] = dic
 
        
def calculate_tgt_stats():    
    global g_tgt_stats_out

    prev_tgt_stats = copy.deepcopy(g_tgt_stats)    
    kstat_update_tgts()    
    g_tgt_stats_out = {}
    
    for key in g_tgt_stats:
        dic = {}
        if key in prev_tgt_stats:
            for d in prev_tgt_stats[key]:
                dic[d] = (g_tgt_stats[key][d] - prev_tgt_stats[key][d]) / g_interval
        else:
            for d in g_tgt_stats[key]:
                dic[d] = g_tgt_stats[key][d] / g_interval
        g_tgt_stats_out[key] = dic

        
def calculate_stats():
    if g_aflag:
        calculate_lun_stats()
        calculate_tgt_stats()
    if g_lflag:
        calculate_lun_stats()
    if g_tflag:
        calculate_tgt_stats()

def prettynum(sz, scale, num=0):
    suffix = [' ', 'K', 'M', 'G', 'T', 'P', 'E', 'Z']
    index = 0
    save = 0

    # Special case for date field
    if scale == -1:
        return "%s" % num
    # Rounding error, return 0
    elif 0 < num < 1:
        num = 0

    while num > scale and index < 5:
        save = num
        num = num / scale
        index += 1

    if index == 0:
        return "%*d" % (sz, num)
    if (save / scale) < 10:
        return "%*.1f%s" % (sz - 1, num, suffix[index])
    else:
        return "%*d%s" % (sz - 1, num, suffix[index])


def print_lun_stats():
    for key in g_lun_stats_out:
        for col in g_hdr:
            if col.find("name") >= 0:
                sys.stdout.write("%s%s" % (g_lun_name[key]["lun-alias"], g_sep))
            else:
                sys.stdout.write("%s%s" % (
                    prettynum(g_cols[col][0], g_cols[col][1], g_lun_stats_out[key][col]), g_sep
                ))
        sys.stdout.write("\n")

    
def print_tgt_stats():
    for key in g_tgt_stats_out:
        for col in g_hdr:
            if col.find("name") >= 0:
                sys.stdout.write("%s%s" % (g_tgt_name[key]["target-name"], g_sep))
            else:
                sys.stdout.write("%s%s" % (
                    prettynum(g_cols[col][0], g_cols[col][1], g_tgt_stats_out[key][col]), g_sep
                ))
        sys.stdout.write("\n")
    

def print_stats():    
    if g_aflag:
        print_lun_stats()
        print_tgt_stats()
    if g_lflag:
        print_lun_stats()
    if g_tflag:
        print_tgt_stats()        
    
            
def print_header():
    for col in g_hdr:
        sys.stdout.write("%*s%s" % (g_cols[col][0], col, g_sep))
    sys.stdout.write("\n")

    
def get_terminal_lines():
    try:
        import fcntl, termios, struct
        data = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, '1234')
        sz = struct.unpack('hh', data)
        return sz[0]
    except:
        pass

        
def update_hdr_intr():
    global g_hdr_intr

    lines = get_terminal_lines()
    if lines and lines > 3:
        g_hdr_intr = lines - 3

        
def resize_handler(signum, frame):
    update_hdr_intr()


def init():
    global g_interval
    global g_count
    global g_hdr
    global g_output_filename
    global g_sep
    global g_output_filehandle
    global g_lflag
    global g_tflag
    global g_aflag

    desired_cols = None
    hflag = False
    vflag = False    
    i = 1

    try:
        opts, args = getopt.getopt(
            sys.argv[1:],
            "o:hvs:f:lta",
            [
                "outfile",
                "help",
                "verbose",
                "seperator",
                "columns",
                "lun",
                "target",
                "all",
            ]
        )
    except getopt.error as msg:
        sys.stderr.write(msg)
        usage()
        opts = None

    for opt, arg in opts:
        if opt in ('-o', '--outfile'):
            g_output_filename = arg
            i += 1
        if opt in ('-h', '--help'):
            hflag = True
        if opt in ('-v', '--verbose'):
            vflag = True
        if opt in ('-s', '--seperator'):
            g_sep = arg
            i += 1
        if opt in ('-f', '--columns'):
            desired_cols = arg
            i += 1
        if opt in ('-l', '--lun'):
            g_lflag = True
        if opt in ('-t', '--target'):
            g_tflag = True
        if opt in ('-a', '--all'):
            g_aflag = True
        i += 1
    
    if g_aflag and (g_lflag or g_tflag):
        usage()      
    if not (g_aflag or g_lflag or g_tflag):
        g_aflag = True
    argv = sys.argv[i:]
    g_interval = Decimal(argv[0]) if argv else g_interval
    g_count = int(argv[1]) if len(argv) > 1 else g_count
    if len(argv) > 1:
        g_interval = Decimal(argv[0])
        g_count = int(argv[1])
    elif len(argv) > 0:
        g_interval = Decimal(argv[0])
        g_count = 0
    if hflag:
        usage()
    if vflag:
        detailed_usage()        
    update_hdr_intr()
    calculate_stats() #clean the initial stats
    if desired_cols:
        g_hdr = desired_cols.split(",")
        invalid = []
        for ele in g_hdr:
            if ele not in g_cols:
                invalid.append(ele)
        if len(invalid) > 0:
            sys.stderr.write("Invalid column definition! -- %s\n" % invalid)
            usage()
    if g_output_filename:
        try:
            g_output_filehandle = open(g_output_filename, "w")
            sys.stdout = g_output_filehandle
        except IOError:
            sys.stderr.write("Cannot open %s for writing\n" % g_output_filename)
            sys.exit(1)

            
def main():
    global g_count    
    count_flag = 0
    
    signal(SIGINT, SIG_DFL)
    signal(SIGWINCH, resize_handler)
    
    init()    
    if g_count > 0:
        count_flag = 1        
    while True:
        print_header()
        calculate_stats()
        print_stats()
        if count_flag == 1:
            if g_count <= 1:
                break
            g_count -= 1
        time.sleep(g_interval)        
    if g_output_filehandle:
        g_output_filehandle.close()
        

if __name__ == '__main__':
    main()
