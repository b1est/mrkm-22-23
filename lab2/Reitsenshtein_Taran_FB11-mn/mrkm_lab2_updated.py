import cpuinfo
import numpy
import os
from nistrng import *

def get_rand_sequence():
    # returns binary array [ 0 1 0 1 .... 0 1 1 0 0 ]
    return pack_sequence(numpy.frombuffer(bytes.fromhex(os.popen("openssl rand -hex 200").read()), dtype=numpy.uint8))
    
def get_rand_sequence_numpy():
    return pack_sequence(numpy.random.randint(-255, 255, 200, dtype=int))

def main():
    print ("Used libs: cpuinfo, numpy, os, nistrng")
    print ("CPU where tests will be performed: " + cpuinfo.get_cpu_info()['brand_raw'] + "\n")
    
    eligible_battery: dict = check_eligibility_all_battery(get_rand_sequence(), SP800_22R1A_BATTERY)

    print("Eligible test from NIST-SP800-22r1a:")
    for name in eligible_battery.keys():
        print("-" + name)
        
    passed_data = dict()
    failed_data = dict()
    
    tests_num = 1000
    
    print ("Performing OpenSSL tests for " + str(tests_num) + " random binary sequences...")
    
    for i in range (0, tests_num):
        binary_sequence = get_rand_sequence()
        
        print ("\nTesting given sequence: " + str(binary_sequence))
        
        results = run_all_battery(binary_sequence, eligible_battery, False)
        
        print("Test results:")
        for result, elapsed_time in results:
            if result.passed:
                data = passed_data.get(result.name)
                
                if data is None:
                    passed_data.update({ result.name: 1 })
                else:
                    passed_data.update({ result.name: data + 1 })
                print("- PASSED - score: " + str(numpy.round(result.score, 3)) + " - " + result.name + " - elapsed time: " + str(elapsed_time) + " ms")
            else:
                data = failed_data.get(result.name)
                
                if data is None:
                    failed_data.update({ result.name: 1 })
                else:
                    failed_data.update({ result.name: data + 1 })
                print("- FAILED - score: " + str(numpy.round(result.score, 3)) + " - " + result.name + " - elapsed time: " + str(elapsed_time) + " ms")
    
    print ("\nPassed tests amount: " + str(passed_data))
    print ("Failed tests amount: " + str(failed_data))
    
    passed_data.clear()
    failed_data.clear()
    
    print ("Performing NumPy tests for " + str(tests_num) + " random binary sequences...")
    
    for i in range (0, tests_num):
        binary_sequence = get_rand_sequence_numpy()
        
        print ("\nTesting given sequence: " + str(binary_sequence))
        
        results = run_all_battery(binary_sequence, eligible_battery, False)
        
        print("Test results:")
        for result, elapsed_time in results:
            if result.passed:
                data = passed_data.get(result.name)
                
                if data is None:
                    passed_data.update({ result.name: 1 })
                else:
                    passed_data.update({ result.name: data + 1 })
                print("- PASSED - score: " + str(numpy.round(result.score, 3)) + " - " + result.name + " - elapsed time: " + str(elapsed_time) + " ms")
            else:
                data = failed_data.get(result.name)
                
                if data is None:
                    failed_data.update({ result.name: 1 })
                else:
                    failed_data.update({ result.name: data + 1 })
                print("- FAILED - score: " + str(numpy.round(result.score, 3)) + " - " + result.name + " - elapsed time: " + str(elapsed_time) + " ms")
    
    print ("\nPassed tests amount: " + str(passed_data))
    print ("Failed tests amount: " + str(failed_data))

if __name__ == '__main__':
    main()