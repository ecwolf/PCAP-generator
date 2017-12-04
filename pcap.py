port = 0

#Custom Foo Protocol Packet
#message =  ('01 01 00 08'   #Foo Base Header
#            '01 02 00 00'   #Foo Message (31 Bytes)
#            '00 00 12 30'   
#            '00 00 12 31'
#            '00 00 12 32' 
#            '00 00 12 33' 
#            '00 00 12 34' 
#            'D7 CD EF'      #Foo flags
#            '00 00 12 35')     

message =  ('7A 58 45 AC'   #Foo Base Header
            '90 DC 5C 82'   #Foo Message (31 Bytes)
            '11 A4 7B bC'   
            '3E 0B 0E 14'
            '66 26 FF FF'
            '66 26')

0000      
0010   
"""----------------------------------------------------------------"""
""" Do not edit below this line unless you know what you are doing """
"""----------------------------------------------------------------"""

import sys
import binascii
import random
from random import shuffle
import os
import string
import sys


#Global header for pcap 2.4
#pcap_global_header =   ('D4 C3 B2 A1'   
#                        '02 00'         #File format major revision (i.e. pcap <2>.4)  
#                        '04 00'         #File format minor revision (i.e. pcap 2.<4>)   
#                        '00 00 00 00'     
#                        '00 00 00 00'     
#                        'FF FF 00 00'     
#                        '01 00 00 00')

pcap_global_header =   ('D4 C3 B2 A1'   
                        '02 00'         #File format major revision (i.e. pcap <2>.4)  
                        '04 00'         #File format minor revision (i.e. pcap 2.<4>)   
                        '00 00 00 00'     
                        '00 00 00 00'     
                        '00 00 04 00'     
                        '01 00 00 00')

#pcap packet header that must preface every packet
pcap_packet_header =   ('AA 77 9F 47'     
                        '90 A2 04 00'     
                        'XX XX XX XX'   #Frame Size (little endian) 
                        'YY YY YY YY')  #Frame Size (little endian)

#eth_header =   ('D0 69 0F A8 39 90'     #Source Mac    
#                'A0 36 9F 3E 94 EA'     #Dest Mac  
#                '08 00')                #Protocol (0x0800 = IP)
eth_header =   ('00 E0 4C 00 00 01'     #Source Mac    
                '00 04 0B 00 00 02'     #Dest Mac  
                '08 00')                #Protocol (0x0800 = IP)

ip_header =    ('45'                    #IP version and header length (multiples of 4 bytes)   
                '00'                      
                'XX XX'                 #Length - will be calculated and replaced later
                '00 00'                   
                '40 00 40'                
                '11'                    #Protocol (0x11 = UDP)          
                'YY YY'                 #Checksum - will be calculated and replaced later      
                '01 01 01 01'           #Source IP (Default: 127.0.0.1)         
                'ZZ ZZ ZZ ZZ')          #Dest IP (Default: 127.0.0.1) 

#udp_header =   ('80 01'                   
#                'XX XX'                 #Port - will be replaced later                   
#                'YY YY'                 #Length - will be calculated and replaced later        
#                '00 00')

udp_header =   ('00 01'                   
                '00 01'                 #Port - will be replaced later                   
                'YY YY'                 #Length - will be calculated and replaced later        
                '00 00')
                
def getByteLength(str1):
    return len(''.join(str1.split())) / 2

def writeByteStringToFile(bytestring, filename):
    bytelist = bytestring.split()  
    bytes = binascii.a2b_hex(''.join(bytelist))
    bitout = open(filename, 'wb')
    bitout.write(bytes)

def generatePCAP(message,port,pcapfile): 

    val1 = 0
    dob = 1
    f = []
    for i in range(252):
        f.append(i+2)
    shuffle(f)
    j = []
    for i in range(253):
        j.append(i)
    
    #udp = udp_header.replace('XX XX',"%04x"%port)
    #udp_len = getByteLength(message) + getByteLength(udp_header)
    #udp = udp.replace('YY YY',"%04x"%udp_len)

    #ip_len = udp_len + getByteLength(ip_header)
    i = 0
    k = 0
    l = 0
    for w in xrange(0,100):
        #udp = udp_header.replace('XX XX',"%04x"%port)
        udp_len = getByteLength(message) + getByteLength(udp_header)
        udp = udp_header.replace('YY YY',"%04x"%udp_len)

        ip_len = udp_len + getByteLength(ip_header)
        if dob == 0: 
            ip = ip_header.replace('ZZ ZZ ZZ ZZ','C0 A8 00 %02x'%f[i]) #%02x'%w value of the last IP byte 
        if dob == 1: 
            ip = ip_header.replace('ZZ ZZ ZZ ZZ','C0 %02x %02x %02x'%(j[l],j[k],f[i])) #%02x'%w value of the last IP byte 
            FILE = "echo  %d.%d.%d.%d  0xa0:0x36:0x9f:0x3e:0x94:0xea 1 >> trace_100_s.txt"%(192,j[l],j[k],f[i])
            #print FILE
            os.system(FILE)
        ip = ip.replace('XX XX',"%04x"%ip_len)
        checksum = ip_checksum(ip.replace('YY YY','00 00'))
        ip = ip.replace('YY YY',"%04x"%checksum)
        
        pcap_len = ip_len + getByteLength(eth_header)
        hex_str = "%08x"%pcap_len
        reverse_hex_str = hex_str[6:] + hex_str[4:6] + hex_str[2:4] + hex_str[:2]
        pcaph = pcap_packet_header.replace('XX XX XX XX',reverse_hex_str)
        pcaph = pcaph.replace('YY YY YY YY',reverse_hex_str)

        #bytestring = pcap_global_header + pcaph + eth_header + ip + udp + message
        if val1 == 1: 
            bytestring = bytestring + pcaph + eth_header + ip + udp + message

        if val1 == 0:
            bytestring = pcap_global_header + pcaph + eth_header + ip + udp + message
            val1 = 1

        w = w + 1    
        i = i + 1   
        if i == 252:
            i = 0
            #print "%d" % k
            k = k + 1
        if k == 253:
            k = 0
            print "%d" % l
            l = l + 1
            #writeByteStringToFile(bytestring, pcapfile)
        if l == 253:
            l = 0
    writeByteStringToFile(bytestring, pcapfile)
        

#Splits the string into a list of tokens every n characters
def splitN(str1,n):
    return [str1[start:start+n] for start in range(0, len(str1), n)]

#Calculates and returns the IP checksum based on the given IP Header
def ip_checksum(iph):

    #split into bytes    
    words = splitN(''.join(iph.split()),4)

    csum = 0;
    for word in words:
        csum += int(word, base=16)

    csum += (csum >> 16)
    csum = csum & 0xFFFF ^ 0xFFFF

    return csum


"""------------------------------------------"""
""" End of functions, execution starts here: """
"""------------------------------------------"""

if len(sys.argv) < 2:
        print 'usage: pcapgen.py output_file'
        exit(0)

generatePCAP(message,port,sys.argv[1])  