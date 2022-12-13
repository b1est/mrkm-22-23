#include <iostream>
#include <openssl/rand.h>
#include "Cephes.h"
#include <cstdlib>
#include <cstdio>
#include <cmath>

extern "C" {
    void  __ogg_fdrffti(int n, double* wsave, int* ifac);
    void  __ogg_fdrfftf(int n, double* X, double* wsave, int* ifac);
}

struct SeqSize
{
    uint64_t size, nob;
    unsigned char* seq;
};

unsigned char* gen(uint64_t size) {
	unsigned char* seq = new unsigned char[size];
    //int i = 0;
	//for (i = 0; i < size; i++) {
	//	RAND_priv_bytes(seq+i, 1);
	//}
    RAND_priv_bytes(seq, size);
    return seq;
}

SeqSize create_seq() {
    uint64_t size = 1000000;
    unsigned char* seq = gen(size);
    uint64_t nob = 8 * size;
    return SeqSize {size, nob, seq};
}

unsigned char get_bit(unsigned char* input, uint64_t input_size, uint64_t pos) {
    if (pos < 0 || pos > input_size * 8)
        throw std::invalid_argument("Invalid pos argument! Must be pos > 0 and pos < size * 8");
    uint64_t elem = pos / 8;
    char location = (8 - (pos % 8)) % 8;
    return (input[elem] & (1 << location)) >> location;
}

double freq_test(SeqSize seq_size) {

    const double sqrt2 = 1.41421356237309504880;

    uint64_t pos;
    double sum = 0.0;
    for (pos = 0; pos < seq_size.nob; pos++)
        sum += (double)((2 * get_bit(seq_size.seq, seq_size.size, pos)) - 1);

    double s_obs = fabs(sum) / sqrt((double)(seq_size.nob));
    double f = s_obs / sqrt2;

    double p_value = erfc(f);

    return p_value;
}

double block_freq_test(uint64_t blockSize, SeqSize seq_size) {

    if (blockSize == 0) {
        blockSize = (seq_size.nob / 100) + 1;
        if (blockSize < 20)
            blockSize = 20;
    }
    else if ((blockSize < 20) || (seq_size.nob / blockSize >= 100)) {
        fprintf(stderr, "BlockFrequencyTest::runTest(): BlockSize M too small:\n"
            "  Let n = M * N :\n"
            "  --> M >= 20, M > 0.01 * n and N < 100\n");
        return 0.0;
    }

    uint64_t i, j, N, blockSum;
    uint64_t M = blockSize;

    double p_value, sum, pi, v, chi_squared;

    N = seq_size.nob / M;

    sum = 0.0;
    uint64_t bit_pos = 0;
    for (i = 0; i < N; ++i) {
        blockSum = 0;
        for (j = 0; j < M; ++j)
            blockSum += get_bit(seq_size.seq, seq_size.size, bit_pos++);

        pi = (double)(blockSum) / (double)(M);
        v = pi - 0.5;
        sum += v * v;
    }
    chi_squared = 4.0 * M * sum;
    p_value = Cephes::cephes_igamc((double)(N) / 2.0, chi_squared / 2.0);

    return p_value;
}

double spect_analysis(SeqSize seq_size) {
    uint64_t bit_pos = 0;

    double p_value, upperBound, percentile, N_l, N_o, d, *m, *X, *wsave;
    wsave = NULL;
    int64_t i, count;
    int ifac[15];
    X = (double*)calloc(seq_size.nob, sizeof(double));
    wsave = (double*)calloc(2 * seq_size.nob, sizeof(double));
    m = (double*)calloc(seq_size.nob / 2 + 1, sizeof(double));
    if ((X == NULL) ||
        (wsave == NULL) ||
        (m == NULL)) {
        fprintf(stderr, "DiscreteFourierTransformTest::runTest(): "
            "Unable to allocate working arrays for the DFT!\n");
        if (X == NULL)
            free(X);
        if (wsave == NULL)
            free(wsave);
        if (m == NULL)
            free(m);
        return 0.0;
    }

    bit_pos = 0;
    for (bit_pos = 0; bit_pos < (int)seq_size.nob; bit_pos++)
        X[bit_pos] = 2 * (get_bit(seq_size.seq, seq_size.size, bit_pos)) - 1;

    __ogg_fdrffti(seq_size.nob, wsave, ifac);
    __ogg_fdrfftf(seq_size.nob, X, wsave, ifac);

    m[0] = sqrt(X[0] * X[0]);	    

    for (i = 0; i < (int)seq_size.nob / 2; i++)
        m[i + 1] = sqrt(pow(X[2 * i + 1], 2) + pow(X[2 * i + 2], 2));

    count = 0;				       
    upperBound = sqrt(2.995732274 * (double)(seq_size.nob));
    for (i = 0; i < (int)seq_size.nob / 2; i++)
        if (m[i] < upperBound)
            count++;
    percentile = (double)count / (double)(seq_size.nob / 2) * 100.0;
    N_l = (double)count;       
    N_o = (double)0.95 * (double)(seq_size.nob) / 2.0;
    d = (N_l - N_o) / sqrt((double)(seq_size.nob) / 4.0 * 0.95 * 0.05);
    p_value = erfc(fabs(d) / sqrt(2.0));

    free(X);
    free(wsave);
    free(m);
    return p_value;
}

double maurer(SeqSize seq_size) {
    uint64_t bit_pos = 0;

    if (seq_size.nob < 387840)
        throw std::invalid_argument("Data should contain at least 387840 bits");
    int		i, j, p, L, Q, K;
    double	arg, sqrt2, sigma, phi, sum, p_value, c;
    long* T, decRep;
    double	expected_value[17] = { 0, 0, 0, 0, 0, 0, 5.2177052, 6.1962507, 7.1836656,
                            8.1764248, 9.1723243, 10.170032, 11.168765,
                            12.168070, 13.167693, 14.167488, 15.167379 };
    double   variance[17] = { 0, 0, 0, 0, 0, 0, 2.954, 3.125, 3.238, 3.311, 3.356, 3.384,
                            3.401, 3.410, 3.416, 3.419, 3.421 };

    if (seq_size.nob >= 387840)     L = 6;
    if (seq_size.nob >= 904960)     L = 7;
    if (seq_size.nob >= 2068480)    L = 8;
    if (seq_size.nob >= 4654080)    L = 9;
    if (seq_size.nob >= 10342400)   L = 10;
    if (seq_size.nob >= 22753280)   L = 11;
    if (seq_size.nob >= 49643520)   L = 12;
    if (seq_size.nob >= 107560960)  L = 13;
    if (seq_size.nob >= 231669760)  L = 14;
    if (seq_size.nob >= 496435200)  L = 15;
    if (seq_size.nob >= 1059061760) L = 16;

    Q = 10 * (int)pow(2, L);
    K = (int)(floor(seq_size.nob / L) - (double)Q);	 		 

    p = (int)pow(2, L);
    T = (long*)calloc(p, sizeof(long));
    if (T == NULL) {
        fprintf(stderr, "MaurersTest::runTest(): "
            "Unable to acquire temp memory!\n");
        return 0.0;
    }

    c = 0.7 - 0.8 / (double)L + (4 + 32 / (double)L) * pow(K, -3 / (double)L) / 15;
    sigma = c * sqrt(variance[L] / (double)K);
    sqrt2 = sqrt(2);
    sum = 0.0;
    for (i = 0; i < p; i++)
        T[i] = 0;
    for (i = 1; i <= Q; i++) {		
        decRep = 0;
        for (j = 0; j < L; j++)
            decRep += get_bit(seq_size.seq, seq_size.size, (i - 1) * L + j) * (long)pow(2, L - 1 - j);
        T[decRep] = i;
    }
    for (i = Q + 1; i <= Q + K; i++) { 
        decRep = 0;
        for (j = 0; j < L; j++)
            decRep += get_bit(seq_size.seq, seq_size.size, (i - 1) * L + j) * (long)pow(2, L - 1 - j);
        sum += log(i - T[decRep]) / log(2);
        T[decRep] = i;
    }
    phi = (double)(sum / (double)K);

    arg = fabs(phi - expected_value[L]) / (sqrt2 * sigma);

    p_value = erfc(arg);

    free(T);

    return p_value;
}

double cumul_sum(int mode, SeqSize seq_size) {
    uint64_t bit_pos = 0;

    if (seq_size.nob < 100) {
        fprintf(stderr, "CumulativeSumsTest::runTest(): Data should contain at least 100 Bits!\n");
        return 0.0;
    }

    int     S, sup, inf, z, zrev, k;
    double  sum1, sum2, p_value;

    z = 0;
    zrev = 0;

    S = 0;
    sup = 0;
    inf = 0;
    for (k = 0; k < (int)seq_size.nob; k++) {
        get_bit(seq_size.seq, seq_size.size, k) ? S++ : S--;
        if (S > sup)
            sup++;
        if (S < inf)
            inf--;
        z = (sup > -inf) ? sup : -inf;
        zrev = (sup - S > S - inf) ? sup - S : S - inf;
    }

    p_value = 0.0;
    if (mode == 0) {
        sum1 = 0.0;
        for (k = (-(int)seq_size.nob / z + 1) / 4; k <= ((int)seq_size.nob / z - 1) / 4; k++) {
            sum1 += Cephes::cephes_normal(((4 * k + 1) * z) / sqrt(seq_size.nob));
            sum1 -= Cephes::cephes_normal(((4 * k - 1) * z) / sqrt(seq_size.nob));
        }
        sum2 = 0.0;
        for (k = (-(int)seq_size.nob / z - 3) / 4; k <= ((int)seq_size.nob / z - 1) / 4; k++) {
            sum2 += Cephes::cephes_normal(((4 * k + 3) * z) / sqrt(seq_size.nob));
            sum2 -= Cephes::cephes_normal(((4 * k + 1) * z) / sqrt(seq_size.nob));
        }

        p_value = 1.0 - sum1 + sum2;
    }
    else {
        sum1 = 0.0;
        for (k = (-(int)seq_size.nob / zrev + 1) / 4; k <= ((int)seq_size.nob / zrev - 1) / 4; k++) {
            sum1 += Cephes::cephes_normal(((4 * k + 1) * zrev) / sqrt(seq_size.nob));
            sum1 -= Cephes::cephes_normal(((4 * k - 1) * zrev) / sqrt(seq_size.nob));
        }
        sum2 = 0.0;
        for (k = (-(int)seq_size.nob / zrev - 3) / 4; k <= ((int)seq_size.nob / zrev - 1) / 4; k++) {
            sum2 += Cephes::cephes_normal(((4 * k + 3) * zrev) / sqrt(seq_size.nob));
            sum2 -= Cephes::cephes_normal(((4 * k + 1) * zrev) / sqrt(seq_size.nob));
        }
        p_value = 1.0 - sum1 + sum2;
    }

    return p_value;
}

int main()
{
    int success_counter = 0;
    int fail_counter = 0;

    for (int i = 0; i < 100; i++) {

        SeqSize seqsize = create_seq();

        double freq_test_res, block_freq_test_res, spectr_analysis_res, maurer_res, cumul_sum_fr_res, cumul_sum_bc_res;

        freq_test_res = freq_test(seqsize);
        block_freq_test_res = block_freq_test(0, seqsize);
        spectr_analysis_res = spect_analysis(seqsize);
        maurer_res = maurer(seqsize);
        cumul_sum_fr_res = cumul_sum(0, seqsize);
        cumul_sum_bc_res = cumul_sum(1, seqsize);

        std::cout << "Iteration " << i+1 << std::endl;
        std::cout << "Frequency test: " << freq_test_res << std::endl;
        std::cout << "Block frequency test: " << block_freq_test_res << std::endl;
        std::cout << "Spectral analysis test: " << spectr_analysis_res << std::endl;
        std::cout << "Maurer statistical test: " << maurer_res << std::endl;
        std::cout << "Cumulative test (forward): " << cumul_sum_fr_res << std::endl;
        std::cout << "Cumulative test (backward): " << cumul_sum_bc_res << std::endl;
        if (freq_test_res < 0.01 || block_freq_test_res < 0.01 || spectr_analysis_res < 0.01 || maurer_res < 0.01 || cumul_sum_fr_res < 0.01 || cumul_sum_bc_res < 0.01) {
            std::cout << "One or more of the tests failed" << std::endl;
            fail_counter++;
        }
        else {
            std::cout << "All tests are passed" << std::endl;
            success_counter++;
        }
        std::cout << std::endl;

        delete[] seqsize.seq;
    }

    std::cout << "Fails: " << fail_counter << std::endl;
    std::cout << "Success: " << success_counter << std::endl;

    return 0;
}
