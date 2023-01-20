CC=g++
PC=python3.9 

PATH_PROF=./prof
PATH_OBJ=./obj

profile_all: $(PATH_PROF)/crypto++_size_prof $(PATH_PROF)/crypto++_time_prof $(PATH_PROF)/OpenSSL_size_prof $(PATH_PROF)/OpenSSL_time_prof $(PATH_PROF)/PyCrypto_size_prof $(PATH_PROF)/PyCrypto_time_prof
	echo ''
	
#* crypto++ profiling
$(PATH_OBJ)/crypto++_size: crypto++_size.cpp
	$(CC) $< -o $@ -g -lcryptopp

$(PATH_OBJ)/crypto++_time: crypto++_time.cpp
	$(CC) $< -o $@ -g -lcryptopp

$(PATH_PROF)/crypto++_size_prof: $(PATH_OBJ)/crypto++_size
	valgrind ./$< > $@ 2>&1

$(PATH_PROF)/crypto++_time_prof: $(PATH_OBJ)/crypto++_time
	./$< > $@ 2>&1 


#* OpenSSL profiling
$(PATH_OBJ)/OpenSSL_size: OpenSSL_size.cpp
	$(CC) $< -o $@ -g -lcrypto

$(PATH_OBJ)/OpenSSL_time: OpenSSL_time.cpp
	$(CC) $< -o $@ -g -lcrypto

$(PATH_PROF)/OpenSSL_size_prof: $(PATH_OBJ)/OpenSSL_size
	valgrind ./$< > $@ 2>&1

$(PATH_PROF)/OpenSSL_time_prof: $(PATH_OBJ)/OpenSSL_time
	./$< > $@ 2>&1


#* PyCrypto (PyCryptodome) profiling
$(PATH_PROF)/PyCrypto_size_prof: PyCrypto_size.py
	$(PC) -m memory_profiler $< > $@ 2>&1

$(PATH_PROF)/PyCrypto_time_prof: PyCrypto_time.py
	$(PC) $< > $@ 2>&1