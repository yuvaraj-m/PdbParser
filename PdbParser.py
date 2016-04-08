import os
import sys
import pefile

for root,dirs,files in os.walk(os.path.abspath(sys.argv[1])):
    for file in files:
        try:
            pe = pefile.PE(os.path.join(root,file))
            for directory in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if directory.name == 'IMAGE_DIRECTORY_ENTRY_DEBUG':
                    if directory.VirtualAddress == 0 | directory.Size ==0 :
                        print file + ",No Debug Directory"
                        break
                    else:
                        pdbflag = False
                        for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                            plocation = dbg.struct.PointerToRawData
                            dtype = dbg.struct.Type
                            dbgsign = pe.get_data(pe.get_rva_from_offset(plocation))[:4]
                            if dbgsign == 'RSDS':
                                if dtype == 2:
                                    print file + ',"'+ pe.get_string_at_rva(pe.get_rva_from_offset(plocation+24)) + '"'
                                    pdbflag = True
                                    break
                        if pdbflag == False:
                            print file + ",No PDB Info"
                        break
        except:
            print file + ",Not a Valid PE File"
