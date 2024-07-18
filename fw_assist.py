#!/usr/bin/env python

#-------------------------------------------------------------------------------
# Name:        fw_assist 
# Purpose:     to analyze assertion and call stack
# Author:      ltang
#-------------------------------------------------------------------------------

import os
import sys
import re
import time
import string
import struct
import types
import socket
import fcntl
import subprocess
import optparse

#-------------------------------------------------------------------------------
# fwa: definition
#-------------------------------------------------------------------------------

# global variables
fwa_opt_version = "%prog v1.0.4"
fwa_opt_usage   = """
%prog [Options]
eg: 
1)How to check DRAM dump
    python3 fw_assist.py --check-dram --dram-file=./fwdump_ar6320v1_dram.txt --fw-path=./ --target=rome_v1.1
2)How to check register dump.
    python3 fw_assist.py --check-regdump --regdump-file=./regdump.txt --fw-path=./ --target=rome_v1.1
""" 
fwa_def_fw_pathname = "./"
fwa_def_ramname = "athwlan.out"
fwa_def_romname = "sw.rom.out"
fwa_def_dram_filename    = "./dram.txt"
fwa_def_regdump_filename = "./regdump.txt"
fwa_def_regdump_size = 16 + 16*4 + 16*10
fwa_cur_regdump_size = 16 + 16*4 + 16*10

fwa_def_stack_symname   = "kernelstack"
fwa_new_stack_symname   = "_new_stack_sentry"
fwa_def_regdump_symname = "current_dump"
# target_name: [stack_start, stack_size, enlarge_size, irom_areas[start, size, ....],  
#                                        iram_areas[start, size, ....]]
fwa_target_info_dict = { \
             "peregrine_v2":[0x409fa4, 0x1000, 0x0,   \
                             [0x940000, 0x40000], [0x980000, 0x50000]], \
             "rome_v1.0":   [0x408b90, 0x1000, 0x0,   \
                             [0x900000, 0x80000], [0x983000, 0x4d000]], \
             "rome_v1.1":   [0x40da40, 0x1000, 0x800, \
                             [0x900000, 0x80000], [0x983000, 0x4d000, 0xa0000, 0x18000]], \
             "rome_v1.3":   [0x40d3d0, 0x1800, 0x0, \
                             [0x900000, 0x80000], [0x983000, 0x4d000, 0xa0000, 0x18000]], \
             "rome_v2.1":   [0x40d3d0, 0x1000, 0x0, \
                             [0x900000, 0x80000], [0x983000, 0x4d000, 0xa0000, 0x18000]], \
            }

#-------------------------------------------------------------------------------
# Common Function
#-------------------------------------------------------------------------------
def os_system(command):
    print( "  [CMD - %s]" % (command))
    return os.system(command)

def os_popen(command):
    print( "  [CMD - %s]" % (command))
    return os.popen(command)

def cmd_getstatusoutput(command):
    print ("  [CMD - %s]" % (command))
    status, output = subprocess.check_output(command).decode()
    return (status, output)

#-------------------------------------------------------------------------------
# fwa_get_symble_address
#-------------------------------------------------------------------------------
def fwa_get_symbol_address(image_filename, symname):
    try:
        # use subprocess.check_output to get command output
        print (" \n [ltang_debug: image_filename - %s symname - %s ]" % (image_filename,symname))
        sym_tbl = subprocess.check_output(["xt-objdump", "-t", image_filename], stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError:
        return False

    # split output and loop each line
    for symline in sym_tbl.split("\n"):
        # use regular expression to match symbol 
        sym_match = re.match(r"^(\w+) .+ %s" % symname, symline)
        if sym_match:
            # convert to hex addr and return 
            symaddr = int(sym_match.group(1), 16)
            return symaddr
    return False


# fwa_create_dram_dict_from_file
def fwa_create_dram_dict_from_file(opts, targ_info, dram_dict):
    sys.stdout.write("checking for DRAM dump file... ")
    if not opts.fwa_dram_filename:
        opts.fwa_dram_filename = fwa_def_dram_filename
        sys.stdout.write("using DEFAULT DRAM file \"%s\"... " % fwa_def_dram_filename)
    dram_filename = opts.fwa_dram_filename

    #ltang add for debug : dram example: fwdump_ar6320v2_dram.txt
    sys.stdout.write("   \" %s \"  " % dram_filename)

    try:
        dramfile = open(dram_filename, "rt")
        dramfile.seek(0, os.SEEK_SET)
        for dline in dramfile:
            item_list = re.split("[\W]+", dline)
            if re.match("0x[0-9a-fA-F]+", item_list[0]):
                addr = int(item_list[0], 16)
                for item in item_list[1:]:
                    if item:
                        dram_dict[addr] = int(item, 16)
                        addr += 4
        dramfile.close()
    except Exception as msg:
        sys.stdout.write("no!\n\n")
        return False
    sys.stdout.write("yes\n")
    return True


#
# fwa_check_callstack_overflow
#

def fwa_check_callstack_overflow(opts, targ_info, dram_dict):
    sys.stdout.write("checking whether callstack overflows... ")
    cs_addr = targ_info[0]
    enlarge_size = targ_info[2]
    for _ in range(2):
        if (cs_addr in dram_dict and
            cs_addr+4 in dram_dict and
            cs_addr+8 in dram_dict and
            cs_addr+12 in dram_dict):
            val1 = dram_dict[cs_addr]
            val2 = dram_dict[cs_addr+4]
            val3 = dram_dict[cs_addr+8]
            val4 = dram_dict[cs_addr+12]
            if (val1 + val2) == 0xffffffff and (val3 + val4) == 0xffffffff:
                sys.stdout.write("no!\n")
                return False
        # print(cs_addr)  # print callstack addr
        cs_addr -= enlarge_size
    sys.stdout.write("yes!\n")
    return True

#
# fwa_create_stack_overflow_info
#
def fwa_create_stack_overflow_info(targ_info, fw_pathname, dram_dict, soline_list):
    sys.stdout.write("creating stack overflow information... ")
    addr = targ_info[0] - targ_info[2]
    
    soline_list.append(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
    soline_list.append("stack on the top:\n")
    soline = "%#.08x:" % addr
    for j in range(4):
        soline += " %#.08x" % dram_dict[addr + j*4]
    soline_list.append("%s\n" % (soline))
    sys.stdout.write("yes\n")
    return True


#
# fwa_create_regdump_dict_from_file
#
def fwa_create_regdump_dict_from_file(opts, targ_info, regdump_dict):
    sys.stdout.write("checking for register dump file... ")
    if not opts.fwa_regdump_filename:
        opts.fwa_regdump_filename = fwa_def_regdump_filename
    regdump_filename = opts.fwa_regdump_filename

    #ltang add for debug : regdump example: 
    sys.stdout.write("   \" %s \"  " % regdump_filename)

    try:
        regdfile = open(regdump_filename, "rt")
        regdfile.seek(0, os.SEEK_SET)
        addr = 0
        for rline in regdfile:
            item_list = re.split("[\W]+", rline)
            for item in item_list:
                if re.match("0x[0-9a-fA-F]+", item):
                    regdump_dict[addr] = int(item, 16)
                    addr += 4
        global fwa_cur_regdump_size    
        fwa_cur_regdump_size = len(regdump_dict.keys()) * 4
        regdfile.close()
    except Exception as msg:
        #print "%s" % msg
        sys.stdout.write("failed!\n\n")
        return False
    sys.stdout.write("yes\n")
    return True


#
# fwa_create_regdump_dict_from_dram
#
def fwa_create_regdump_dict_from_dram(targ_info, fw_pathname, dram_dict, regdump_dict):
    sys.stdout.write("checking whether there is an assertion... ")
    rom_filename = os.path.join(fw_pathname, fwa_def_romname)
    # check sw.rom.out
    regdump_addr = fwa_get_symbol_address(rom_filename, fwa_def_regdump_symname)

    #ltang add for debug : regdump example: 
    sys.stdout.write("   rom_file: %s regdummp_symname:%s  " % (rom_filename,fwa_def_regdump_symname))

    if not regdump_addr or regdump_addr not in dram_dict:
        sys.stdout.write("no!\n")
        return False

    rdstart = dram_dict[regdump_addr]
    rdsize  = min([fwa_def_regdump_size, fwa_cur_regdump_size])
    addr = rdstart 
    while addr < rdstart + rdsize:
#        if not dram_dict.has_key(addr):
        if addr not in dram_dict:
            return False
        regdump_dict[addr] = dram_dict[addr]
        addr += 4
    sys.stdout.write("yes\n")
    return True

#
# fwa_create_assert_output_info
#
def fwa_create_assert_output_info(targ_info, fw_pathname, regdump_dict, asline_list):
    sys.stdout.write("creating assertion information... ")
    rdstart = min(regdump_dict.keys())
    #print "regdump_start = %#.08x" % rdstart
    tid_val = line_val = pc_val = va_val = 0

    if rdstart in regdump_dict:
        tid_val = regdump_dict[rdstart]

    if rdstart+4 in regdump_dict:
        line_val = regdump_dict[rdstart+4]

    if rdstart+8 in regdump_dict:
        pc_val = regdump_dict[rdstart+8]

    if rdstart+12 in regdump_dict:
        va_val = regdump_dict[rdstart+12]

    epc1 = epc2 = epc3 = epc4 = 0

    if rdstart+16*4 in regdump_dict:
        epc1 = regdump_dict[rdstart+16*4]

    if rdstart+16*4+4 in regdump_dict:
        epc2 = regdump_dict[rdstart+16*4+4]

    if rdstart+16*4+8 in regdump_dict:
        epc3 = regdump_dict[rdstart+16*4+8]

    if rdstart+16*4+12 in regdump_dict:
        epc4 = regdump_dict[rdstart+16*4+12]
    
    asline_list.append(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
    asline_list.append("assertion information:\n")
    asline_list.append("%#.08x : Target ID\n" % tid_val)
    asline_list.append("%#.08x : Line Number when assertion\n" % line_val)
    asline_list.append("%#.08x : Program Counter when assertion%s\n" % \
            (pc_val, fwa_get_info_from_pcaddr(targ_info, fw_pathname, pc_val)))
    asline_list.append("%#.08x : Virtual Address causing exception\n" % (va_val))
    asline_list.append("%#.08x : EPC1%s\n" % (epc1,
        fwa_get_info_from_pcaddr(targ_info, fw_pathname, epc1)))
    asline_list.append("%#.08x : EPC2%s\n" % (epc2,
        fwa_get_info_from_pcaddr(targ_info, fw_pathname, epc2)))
    asline_list.append("%#.08x : EPC3%s\n" % (epc3,
        fwa_get_info_from_pcaddr(targ_info, fw_pathname, epc3)))
    asline_list.append("%#.08x : EPC4%s\n" % (epc4,
        fwa_get_info_from_pcaddr(targ_info, fw_pathname, epc4)))

    # print on the screan
    sys.stdout.write("yes\n")
    sys.stdout.write(asline_list[0])
    for asline in asline_list[1:]:
        sys.stdout.write(">  %s" % asline)
    sys.stdout.write(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")

    return True

#
# fwa_create_regdump_output_info
#
def fwa_create_regdump_output_info(targ_info, fw_pathname, regdump_dict, rdline_list):
    sys.stdout.write("creating register dump structure... ")
    rdstart = min(regdump_dict.keys())
    rdsize  = min([fwa_def_regdump_size, fwa_cur_regdump_size])
    addr = rdstart 
    #print "regdump_start = %#.08x, redsize = %#.08x" % (rdstart, rdsize)
    rdline_list.append(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
    rdline_list.append("register dump structure:\n")
    while addr < rdstart + rdsize:
        regdump_line = "%#.08x:" % addr
        for j in range(4):
            regdump_line += " %#.08x" % regdump_dict[addr + j*4]
        if (addr - rdstart) >= (16*5):
            regdump_line += fwa_get_info_from_pcaddr(targ_info, fw_pathname, regdump_dict[addr])
        
        rdline_list.append("%s\n" % (regdump_line))
        addr += 16

    # print on the screen
    sys.stdout.write("yes\n")
    sys.stdout.write(rdline_list[0])
    for rdline in rdline_list[1:]:
        sys.stdout.write(">  %s" % rdline)
    sys.stdout.write(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")

    return True
    
#
# fwa_check_call_stack
#
def fwa_check_call_stack(targ_info, dram_dict):
    sys.stdout.write("checking whether call stack is integral(start=%#x, size=%#x)... " % \
                     (targ_info[0]-targ_info[2], targ_info[1]+targ_info[2]))
    csstart = targ_info[0] - targ_info[2]
    csend   = csstart + targ_info[1] + targ_info[2]
    addr = csstart
    while addr < csend:
        if addr not in dram_dict:
            # print "---- error addr = %x" % addr
            sys.stdout.write("no!\n")
            return False
        addr += 4
    sys.stdout.write("yes\n")
    return True

#
# fwa_create_stack_output_info
#
def fwa_create_stack_output_info(targ_info, fw_pathname, dram_dict, csline_list):
    sys.stdout.write("creating call stack... ")
    csstart = targ_info[0] - targ_info[2]
    csend   = csstart + targ_info[1] + targ_info[2]
    addr = csstart
    
    csline_list.append(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
    csline_list.append("call stack:\n")
    while addr < csend:
        csline = "%#.08x:" % addr
        for j in range(4):
            csline += " %#.08x" % dram_dict[addr + j*4]
        csline += fwa_get_info_from_pcaddr(targ_info, fw_pathname, dram_dict[addr])
        
        csline_list.append("%s\n" % (csline))
        addr += 16

    sys.stdout.write("yes\n")
    return True


#
# fwa_create_corefmt_output_info
#
def fwa_create_corefmt_output_info(dram_dict, dramline_list):
    sys.stdout.write("creating core format dump... ")
    dramstart = min(dram_dict.keys())
    dramsize  = len(dram_dict.keys())
    addr = dramstart 
    while addr < dramstart + dramsize:
        if addr in dram_dict:
            dramline_list.append("%#.08x:%#.08x\n" % (addr, dram_dict[addr]))
        addr += 4

    sys.stdout.write("yes\n")
    return True
    
#
# fwa_create_output_file
#
def fwa_create_output_file(opts, output_area_list):
    sys.stdout.write("creating output file... " ) 
    if not opts.fwa_output_filename:
        sys.stdout.write("no output filename!\n\n" )
        return False

    sys.stdout.write("\"%s\"... " % opts.fwa_output_filename) 
    output_filename = opts.fwa_output_filename

    try:
        outfile = open(output_filename, "wt")
        for output_area in output_area_list:
            for line in output_area:
                outfile.write(line)
        outfile.close()
    except Exception as msg:
        sys.stdout.write("failed!\n\n")
        return False
    sys.stdout.write("yes\n" )
    return True
     

def fwa_get_info_from_pcaddr(targ_info, fw_pathname, viraddr):
    iram_areas = targ_info[-1]
    irom_areas = targ_info[-2]

    # according viraddr to calc phyaddr 
    if viraddr > 0xC0000000:
        phyaddr = viraddr - 0xC0000000
    elif viraddr > 0x80000000:
        phyaddr = viraddr - 0x80000000
    elif viraddr > 0x40000000:
        phyaddr = viraddr - 0x40000000
    else:
        phyaddr = viraddr

    rom_filename = os.path.join(fw_pathname, fwa_def_romname)
    ram_filename = os.path.join(fw_pathname, fwa_def_ramname)

    status, info = (0x1, "")

    num_irom = len(irom_areas) // 2
    for num in range(num_irom):
        start = irom_areas[num * 2]
        end   = start + irom_areas[num * 2 + 1]
        if phyaddr >= start and phyaddr < end:
            try:
                info = subprocess.check_output(["xt-addr2line", "-f", "-e", rom_filename, hex(phyaddr)], stderr=subprocess.STDOUT).decode()
                status = 0
            except subprocess.CalledProcessError:
                pass
            break

    if status == 0 and info:
        parts = re.split("[\n|:]", info.strip())
        funcname, filename, linenum = parts[:3]
        filename = os.path.basename(filename)
        return "  --  %s, %s:%s" % (funcname, filename, linenum)

    num_iram = len(iram_areas) // 2
    for num in range(num_iram):
        start = iram_areas[num * 2]
        end   = start + iram_areas[num * 2 + 1]
        if phyaddr >= start and phyaddr < end:
            try:
                info = subprocess.check_output(["xt-addr2line", "-f", "-e", ram_filename, hex(phyaddr)], stderr=subprocess.STDOUT).decode()
                status = 0
            except subprocess.CalledProcessError:
                pass
            break

    if status == 0 and info:
        parts = re.split("[\n|:]", info.strip())
        funcname, filename, linenum = parts[:3]
        filename = os.path.basename(filename)
        return "  --  %s, %s:%s" % (funcname, filename, linenum)

    return ""

    
    
#python 3    
def fwa_check_xtenv():
    sys.stdout.write("checking for extensa environment... ")
    command = ["xt-addr2line", "-v"]
    
    try:
        # use subprocess.run()，and redirect std out to /dev/null
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
        sys.stdout.write("yes\n")
        return True
    except subprocess.CalledProcessError:
        # 
        sys.stdout.write("no!\n\n")
        return False

#
# check fw ram & rom
#
def fwa_check_fw_files(opts, fw_pathname_list):
    sys.stdout.write("checking for fw pathname... ")
    if not opts.fwa_fw_pathname:
        opts.fwa_fw_pathname = fwa_def_fw_pathname
        sys.stdout.write("using DEFAULT path name \"%s\"... " % fwa_def_fw_pathname)
    fw_pathname = opts.fwa_fw_pathname
    fw_pathname_list.append(fw_pathname)

    # check whether rom & ram exist.
    found_fw_rom = found_fw_ram = False
    name_list = os.listdir(fw_pathname)
    for name in name_list:
        fw_filename = os.path.join(fw_pathname, name)
        if os.path.isfile(fw_filename):
            if name == fwa_def_ramname:
                found_fw_ram = True
            if name == fwa_def_romname:
                found_fw_rom = True
            if found_fw_ram and found_fw_rom:
                break
    if not found_fw_rom and not found_fw_ram:
        sys.stdout.write("%s or %s doesn't exist in the %s!\n\n" % \
                (fwa_def_ramname, fwa_def_romname, fw_pathname))
        return False
    sys.stdout.write("yes\n")
    return True

#
# fwa_check_target_name
#
def fwa_check_target_name(opts, fw_pathname, targ_info_list):
    sys.stdout.write("checking for target name... ")
    found_target_info = False

    if not opts.fwa_target:
        opts.fwa_target = fwa_target_info_dict.keys()[-1]
        sys.stdout.write("using DEFAULT target name \"%s\"... " % opts.fwa_target)

    for targ_name in fwa_target_info_dict.keys():
        if opts.fwa_target == targ_name:
            targ_info_list.append(fwa_target_info_dict[targ_name])
            found_target_info = True
            break;

    if not found_target_info:
        sys.stdout.write("don't support \"%s\"!\n\n" % opts.fwa_target)
        return False

    retval = fwa_get_symbol_address(os.path.join(fw_pathname, fwa_def_romname), \
                                    fwa_def_stack_symname)
    if retval:
        #print "%#.08x found kernel stack" % retval
        targ_info_list[-1][0] = retval

    if targ_name == "rome_v2.1":
        retval = fwa_get_symbol_address(os.path.join(fw_pathname, fwa_def_ramname), \
                                    fwa_new_stack_symname)
        if retval:
            targ_info_list[-1][0] = retval
            targ_info_list[-1][1] = 0x1800 
            #print "%#.08x, %#.08x found kernel stack" % (targ_info_list[-1][0], targ_info_list[-1][1])

    if opts.enlarge_stack != 0xffffffff:
        if opts.enlarge_stack % 0x10:
            opts.enlarge_stack = opts.enlarge_stack + 0x10 - (opts.enlarge_stack % 16)
        targ_info_list[-1][2] = opts.enlarge_stack  
    #targ_info_list[-1][0] -= targ_info_list[-1][2]
    #targ_info_list[-1][1] += targ_info_list[-1][2]

    sys.stdout.write("yes\n")
    return True

#-------------------------------------------------------------------------------
# fwa_chkdram_main
#-------------------------------------------------------------------------------
def fwa_chkdram_main(opts, args):
    sys.stdout.write("starting to analyze DRAM dump file...\n")

    # step1, checking for extensa environment
    if not fwa_check_xtenv():
        return False

    # step2, handle opts.fwa_fw_pathname
    fw_pathname_list = []
    retval = fwa_check_fw_files(opts, fw_pathname_list)
    if not retval or not fw_pathname_list:
        return False
    fw_pathname = fw_pathname_list[-1]


    # step3, handling opts.fwa_target
    targ_info_list = []
    retval = fwa_check_target_name(opts, fw_pathname, targ_info_list)
    if not retval or not targ_info_list:
        return False;
    targ_info = targ_info_list[-1]


    # step4, handle opts.fwa_dram_file
    dram_dict = {}
    if not fwa_create_dram_dict_from_file(opts, targ_info, dram_dict):
        return False 

    # step5, checking whether callstack overflows...
    found_overflow = fwa_check_callstack_overflow(opts, targ_info, dram_dict)

    # step5,
    regdump_dict = {}
    found_assertion = fwa_create_regdump_dict_from_dram(targ_info, fw_pathname, dram_dict, regdump_dict)

    # step6,
    asline_list = []
    if found_assertion:
        fwa_create_assert_output_info(targ_info, fw_pathname, regdump_dict, asline_list)

    # step7,
    rdline_list = []
    if found_assertion:
        fwa_create_regdump_output_info(targ_info, fw_pathname, regdump_dict, rdline_list)

    # step8,
    found_callstack = fwa_check_call_stack(targ_info, dram_dict)

    # step9,
    csline_list = []
    if found_callstack:
        fwa_create_stack_output_info(targ_info, fw_pathname, dram_dict, csline_list)

    # step10,
    if not opts.fwa_output_filename:
        dram_pathname, dram_basename = os.path.split(opts.fwa_dram_filename)
        output_basename = "chkdram_output_%s" % dram_basename
        opts.fwa_output_filename = os.path.join(dram_pathname, output_basename)
    if not fwa_create_output_file(opts, [asline_list, rdline_list, csline_list]):
        return False        
    
    return True



#-------------------------------------------------------------------------------
# fwa_chkregd_main
#-------------------------------------------------------------------------------
def fwa_chkregd_main(opts, args):
    sys.stdout.write("starting to analyze register dump file...\n")

    # step1, checking for extensa environment
    if not fwa_check_xtenv():
        return False

    # step2, handle opts.fwa_fw_pathname
    fw_pathname_list = []
    retval = fwa_check_fw_files(opts, fw_pathname_list)
    if not retval or not fw_pathname_list:
        return False
    fw_pathname = fw_pathname_list[-1]


    # step3, handling opts.fwa_target
    targ_info_list = []
    retval = fwa_check_target_name(opts, fw_pathname, targ_info_list)
    if not retval or not targ_info_list:
        return False;
    targ_info = targ_info_list[-1]

    # step4, handle opts.fwa_regdump_filename
    regdump_dict = {}
    if not fwa_create_regdump_dict_from_file(opts, targ_info, regdump_dict):
        return False

    # step5,
    asline_list = []
    fwa_create_assert_output_info(targ_info, fw_pathname, regdump_dict, asline_list)

    # step6,
    rdline_list = []
    fwa_create_regdump_output_info(targ_info, fw_pathname, regdump_dict, rdline_list)

    # step7,
    if not opts.fwa_output_filename:
        regdump_pathname, regdump_basename = os.path.split(opts.fwa_regdump_filename)
        output_basename = "chkregdump_output_%s" % regdump_basename
        opts.fwa_output_filename = os.path.join(regdump_pathname, output_basename)
    if not fwa_create_output_file(opts, [asline_list, rdline_list]):
        return False        
    
    return True


#-------------------------------------------------------------------------------
# fwa_xlatecorefmt_main
#-------------------------------------------------------------------------------
def fwa_xlatecorefmt_main(opts, args):
    sys.stdout.write("starting to translate DRAM to format used by core_file_gen......\n")

    # step1, handle opts.fwa_dram_file
    dram_dict = {}
    if not fwa_create_dram_dict_from_file(opts, [], dram_dict):
        return False 

    # step2,
    dramline_list = []
    if not fwa_create_corefmt_output_info(dram_dict, dramline_list):
        return False

    # step3,
    if not opts.fwa_output_filename:
        dram_pathname, dram_basename = os.path.split(opts.fwa_dram_filename)
        output_basename = "corefmt_%s" % dram_basename
        opts.fwa_output_filename = os.path.join(dram_pathname, output_basename)
    if not fwa_create_output_file(opts, [dramline_list]):
        return False        
    
    return True


#-------------------------------------------------------------------------------
# option parse
#-------------------------------------------------------------------------------
def parse_options():
    parser = optparse.OptionParser(usage=fwa_opt_usage, version=fwa_opt_version)
    parser.add_option("-D", "--check-dram", dest="check_dram",
                      action="store_true", default=False,                  
                      help="analyze assertion and call stack with DRAM dump")

    parser.add_option("-R", "--check-regdump", dest="check_regdump",
                      action="store_true", default=False,                  
                      help="analyze assertion and call stack with register dump")

    parser.add_option("-C", "--xlate-corefmt", dest="xlate_corefmt",
                      action="store_true", default=False,                  
                      help="translate DRAM to the format used by core_dump_gen")

    #
    # command options for checking call stack
    #
    mtq_group = optparse.OptionGroup(parser, "[-D|-R|-C] Options",
                                     "all sub-options for [-D|-R|-C]")
    mtq_group.add_option("-t", "--target", dest="fwa_target", metavar="NAME",
                         action="store", type="string", default="",
                         help="support peregrine_v2, rome_v1.0, rome_v1.1, rome_v1.3")

    mtq_group.add_option("-f", "--fw-path", dest="fwa_fw_pathname", metavar="PATH",
                         action="store", type="string", default="",
                         help="path of athwlan.out and sw.rom.out")

    mtq_group.add_option("-d", "--dram-file", dest="fwa_dram_filename", metavar="FILE",
                         action="store", type="string", default="",
                         help="FW DRAM dump file")

    mtq_group.add_option("-r", "--regdump-file", dest="fwa_regdump_filename", metavar="FILE",
                         action="store", type="string", default="",
                         help="FW register dump file")

    mtq_group.add_option("-l", "--enlarge-stack", dest="enlarge_stack", metavar="SIZE",
                         action="store", type="int", default=0xffffffff,
                         help="enlarge callstack on the top"),


    mtq_group.add_option("-o", "--output-file", dest="fwa_output_filename", metavar="FILE",
                         action="store", type="string", default="",
                         help="output file generated by fw_assist.py")
    parser.add_option_group(mtq_group)

    (opts, args) = parser.parse_args()
    return opts, args

#-------------------------------------------------------------------------------
# main function
#-------------------------------------------------------------------------------
def main():
    ret = True
    if sys.platform != "linux":
        print( "  [sys.platform = %s]" % (sys.platform))
        sys.stdout.write("Warning: Please run fw_assist on the linux OS!\n")
        return False

    opts, args = parse_options()
    #print opts
    if ret and opts.check_dram:
        sys.stdout.write("-------------------------------------------------------------------------------\n")
        ret = fwa_chkdram_main(opts, args)

    # do next action if the previous action success
    if ret and opts.check_regdump:
        sys.stdout.write("-------------------------------------------------------------------------------\n")
        ret = fwa_chkregd_main(opts, args)
    
    # do next action if the previous action success
    if ret and opts.xlate_corefmt:
        sys.stdout.write("-------------------------------------------------------------------------------\n")
        ret = fwa_xlatecorefmt_main(opts, args)
    return ret

if __name__ == '__main__':
    main()
