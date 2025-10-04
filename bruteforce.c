#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>

void decrypt(long key, char *ciph, int len){
  // Preparar la llave DES
  DES_cblock des_key;
  DES_key_schedule schedule;
  
  // Convertir long a DES key con paridad
  long k = 0;
  for(int i=0; i<8; ++i){
    key <<= 1;
    k += (key & (0xFE << i*8));
  }
  
  // Copiar a DES_cblock
  memcpy(&des_key, &k, 8);
  
  // Establecer paridad
  DES_set_odd_parity(&des_key);
  
  // Crear key schedule
  DES_set_key_unchecked(&des_key, &schedule);
  
  // Descifrar en bloques de 8 bytes
  for(int i=0; i<len; i+=8){
    DES_ecb_encrypt((DES_cblock *)(ciph+i), 
                    (DES_cblock *)(ciph+i), 
                    &schedule, 
                    DES_DECRYPT);
  }
}

void encrypt(long key, char *ciph, int len){
  // Preparar la llave DES
  DES_cblock des_key;
  DES_key_schedule schedule;
  
  // Convertir long a DES key con paridad
  long k = 0;
  for(int i=0; i<8; ++i){
    key <<= 1;
    k += (key & (0xFE << i*8));
  }
  
  // Copiar a DES_cblock
  memcpy(&des_key, &k, 8);
  
  // Establecer paridad
  DES_set_odd_parity(&des_key);
  
  // Crear key schedule
  DES_set_key_unchecked(&des_key, &schedule);
  
  // Cifrar en bloques de 8 bytes
  for(int i=0; i<len; i+=8){
    DES_ecb_encrypt((DES_cblock *)(ciph+i), 
                    (DES_cblock *)(ciph+i), 
                    &schedule, 
                    DES_ENCRYPT);
  }
}

// ==================== Utilidades para archivo y padding ====================
// Lee archivo completo en memoria en binario y devuelve el buffer y longitud
static unsigned char* read_file_all(const char *path, size_t *out_len){
  *out_len = 0;
  FILE *f = fopen(path, "rb");
  if(!f) { perror("fopen input"); return NULL; }
  if(fseek(f, 0, SEEK_END) != 0){ perror("fseek"); fclose(f); return NULL; }
  long sz = ftell(f);
  if(sz < 0){ perror("ftell"); fclose(f); return NULL; }
  rewind(f);

  if(sz == 0){
  }

  unsigned char *buf = (unsigned char*)malloc((size_t)sz);
  if(!buf){ perror("malloc"); fclose(f); return NULL; }

  size_t n = fread(buf, 1, (size_t)sz, f);
  if(n != (size_t)sz){
    perror("fread");
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *out_len = n;
  return buf;
}

// Escribe el buffer completo en binario
static int write_file_all(const char *path, const unsigned char *buf, size_t len){
  FILE *f = fopen(path, "wb");
  if(!f){ perror("fopen output"); return -1; }
  size_t n = fwrite(buf, 1, len, f);
  if(n != len){ perror("fwrite"); fclose(f); return -1; }
  fclose(f);
  return 0;
}

// Aplicar padding para DES bloques de 8. Devuelve nuevo buffer y longitud
static unsigned char* pkcs7_pad_8(const unsigned char *in, size_t in_len, size_t *out_len){
  const size_t block = 8;
  size_t pad = block - (in_len % block);
  if(pad == 0) pad = block;
  *out_len = in_len + pad;

  unsigned char *out = (unsigned char*)malloc(*out_len);
  if(!out){ perror("malloc pad"); return NULL; }
  if(in_len) memcpy(out, in, in_len);
  memset(out + in_len, (int)pad, pad);
  return out;
}

// ==================== Cifrar archivo ====================
static long parse_key(const char *s){
  char *end = NULL;
  unsigned long v = strtoul(s, &end, 0);
  if(end == s){
    fprintf(stderr, "Clave inválida: %s\n", s);
    exit(1);
  }
  return (long)v;
}

static int encrypt_file_with_key(long key, const char *inpath, const char *outpath){
  size_t plain_len = 0;
  unsigned char *plain = read_file_all(inpath, &plain_len);
  if(!plain){
    fprintf(stderr, "No se pudo leer el archivo de entrada.\n");
    return -1;
  }

  size_t padded_len = 0;
  unsigned char *padded = pkcs7_pad_8(plain, plain_len, &padded_len);
  free(plain);
  if(!padded){
    fprintf(stderr, "Fallo el padding.\n");
    return -1;
  }

  // Cifrado encrypt() usa char* y longitud múltiplo de 8
  encrypt(key, (char*)padded, (int)padded_len);

  int rc = write_file_all(outpath, padded, padded_len);
  free(padded);

  if(rc == 0){
    printf("Cifrado OK. Escrito %zu bytes en '%s'.\n", padded_len, outpath);
  }
  return rc;
}

char search[] = " the ";

int tryKey(long key, char *ciph, int len){
  char temp[len+1];
  memcpy(temp, ciph, len);
  temp[len]=0;
  decrypt(key, temp, len);
  return strstr((char *)temp, search) != NULL;
}

unsigned char cipher[] = {108, 245, 65, 63, 125, 200, 150, 66, 17, 170, 207, 170, 34, 31, 70, 215, 0};

// ==================== main ====================
int main(int argc, char *argv[]){

  // COMPILAR: mpicc -O2 -o bruteforce bruteforce.c -lcrypto
  // CIFRADO: ./bruteforce -e <llave> <input.txt> <cifrado.des>
  if(argc == 5 && strcmp(argv[1], "-e") == 0){
    long key = parse_key(argv[2]);
    const char *inpath  = argv[3];
    const char *outpath = argv[4];
    return encrypt_file_with_key(key, inpath, outpath) == 0 ? 0 : 1;
  }

  int N, id;
  long upper = (1L << 56);
  long mylower, myupper;
  MPI_Status st;
  MPI_Request req;
  int ciphlen = strlen((char *)cipher);
  MPI_Comm comm = MPI_COMM_WORLD;

  MPI_Init(&argc, &argv);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);

  long range_per_node = upper / N;
  mylower = range_per_node * id;
  myupper = range_per_node * (id+1) - 1;
  if(id == N-1){
    myupper = upper;
  }

  long found = 0;
  MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);

  for(long i = mylower; i < myupper && (found == 0); ++i){
    if(tryKey(i, (char *)cipher, ciphlen)){
      found = i;
      for(int node = 0; node < N; node++){
        MPI_Send(&found, 1, MPI_LONG, node, 0, MPI_COMM_WORLD);
      }
      break;
    }
  }

  if(id == 0){
    MPI_Wait(&req, &st);
    decrypt(found, (char *)cipher, ciphlen);
    printf("Llave encontrada: %li\n", found);
    printf("Texto descifrado: %s\n", cipher);
  }

  MPI_Finalize();
  return 0;
}