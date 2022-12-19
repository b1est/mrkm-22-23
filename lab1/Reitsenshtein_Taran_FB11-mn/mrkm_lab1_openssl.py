import os
import cpuinfo

def main():
    print ("Used libs: os, cpuinfo")
    print ("CPU where tests will be performed: " + cpuinfo.get_cpu_info()['brand_raw'] + "\n")
    
    for i in range(1000, 10500, 500):
        print ("Testing rsa2048, sha256 and aes-256-cbc with random " + str(i) + " bytes.")
        os.system("openssl speed -bytes " + str(i) + " rsa2048 sha256 aes-256-cbc")
        print ("\n")
    

if __name__ == '__main__':
    main()