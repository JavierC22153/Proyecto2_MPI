#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <mpi.h>
#include <unistd.h>
#include <openssl/des.h>

// ==================== DES ====================
void decrypt(long key, char *ciph, int len)
{
  DES_cblock des_key;
  DES_key_schedule schedule;

  long k = 0;
  for (int i = 0; i < 8; ++i)
  {
    key <<= 1;
    k += (key & (0xFEL << (i * 8)));
  }

  memcpy(&des_key, &k, 8);
  DES_set_odd_parity(&des_key);
  DES_set_key_unchecked(&des_key, &schedule);

  for (int i = 0; i < len; i += 8)
  {
    DES_ecb_encrypt((DES_cblock *)(ciph + i),
                    (DES_cblock *)(ciph + i),
                    &schedule,
                    DES_DECRYPT);
  }
}

void encrypt(long key, char *ciph, int len)
{
  DES_cblock des_key;
  DES_key_schedule schedule;

  long k = 0;
  for (int i = 0; i < 8; ++i)
  {
    key <<= 1;
    k += (key & (0xFEL << (i * 8)));
  }

  memcpy(&des_key, &k, 8);
  DES_set_odd_parity(&des_key);
  DES_set_key_unchecked(&des_key, &schedule);

  for (int i = 0; i < len; i += 8)
  {
    DES_ecb_encrypt((DES_cblock *)(ciph + i),
                    (DES_cblock *)(ciph + i),
                    &schedule,
                    DES_ENCRYPT);
  }
}

// ==================== Utilidades ====================
static unsigned char *read_file_all(const char *path, size_t *out_len)
{
  *out_len = 0;
  FILE *f = fopen(path, "rb");
  if (!f)
  {
    perror("fopen input");
    return NULL;
  }
  if (fseek(f, 0, SEEK_END) != 0)
  {
    perror("fseek");
    fclose(f);
    return NULL;
  }
  long sz = ftell(f);
  if (sz < 0)
  {
    perror("ftell");
    fclose(f);
    return NULL;
  }
  rewind(f);

  unsigned char *buf = (unsigned char *)malloc((size_t)sz);
  if (!buf)
  {
    perror("malloc");
    fclose(f);
    return NULL;
  }

  size_t n = fread(buf, 1, (size_t)sz, f);
  if (n != (size_t)sz)
  {
    perror("fread");
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  *out_len = n;
  return buf;
}

static int write_file_all(const char *path, const unsigned char *buf, size_t len)
{
  FILE *f = fopen(path, "wb");
  if (!f)
  {
    perror("fopen output");
    return -1;
  }
  size_t n = fwrite(buf, 1, len, f);
  if (n != len)
  {
    perror("fwrite");
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

static unsigned char *pkcs7_pad_8(const unsigned char *in, size_t in_len, size_t *out_len)
{
  const size_t block = 8;
  size_t pad = block - (in_len % block);
  if (pad == 0)
    pad = block;
  *out_len = in_len + pad;

  unsigned char *out = (unsigned char *)malloc(*out_len);
  if (!out)
  {
    perror("malloc pad");
    return NULL;
  }
  if (in_len)
    memcpy(out, in, in_len);
  memset(out + in_len, (int)pad, pad);
  return out;
}

static long parse_key(const char *s)
{
  char *end = NULL;
  unsigned long v = strtoul(s, &end, 0);
  if (end == s)
  {
    fprintf(stderr, "Clave inválida: %s\n", s);
    exit(1);
  }
  return (long)v;
}

static int encrypt_file_with_key(long key, const char *inpath, const char *outpath)
{
  size_t plain_len = 0;
  unsigned char *plain = read_file_all(inpath, &plain_len);
  if (!plain)
  {
    fprintf(stderr, "No se pudo leer el archivo de entrada.\n");
    return -1;
  }

  size_t padded_len = 0;
  unsigned char *padded = pkcs7_pad_8(plain, plain_len, &padded_len);
  free(plain);
  if (!padded)
  {
    fprintf(stderr, "Fallo el padding.\n");
    return -1;
  }

  encrypt(key, (char *)padded, (int)padded_len);

  int rc = write_file_all(outpath, padded, padded_len);
  free(padded);

  if (rc == 0)
  {
    printf("Cifrado OK. Escrito %zu bytes en '%s'.\n", padded_len, outpath);
  }
  return rc;
}

// ==================== Búsqueda ====================
static char search[256] = "test";

int tryKey(long key, char *ciph, int len)
{
  char *temp = (char *)malloc((size_t)len + 1);
  if (!temp)
  {
    perror("malloc tryKey");
    return 0;
  }
  memcpy(temp, ciph, (size_t)len);
  temp[len] = 0;
  decrypt(key, temp, len);
  int ok = (strstr((char *)temp, search) != NULL);
  free(temp);
  return ok;
}

// ==================== main ====================
int main(int argc, char *argv[])
{
  if (argc == 5 && strcmp(argv[1], "-e") == 0)
  {
    long key = parse_key(argv[2]);
    const char *inpath = argv[3];
    const char *outpath = argv[4];
    return encrypt_file_with_key(key, inpath, outpath) == 0 ? 0 : 1;
  }

  if (argc < 3)
  {
    fprintf(stderr, "Uso:\n");
    fprintf(stderr, "  Cifrar:     ./bruteforce -e <llave> <input.txt> <output.des>\n");
    fprintf(stderr, "  Bruteforce: mpirun -np <N> ./bruteforce <cifrado.des> <palabra> [llave_max] [modo]\n");
    fprintf(stderr, "\nModos de distribución:\n");
    fprintf(stderr, "  0 = Secuencial por bloques (default)\n");
    fprintf(stderr, "  1 = Intercalado (interleaved)\n");
    fprintf(stderr, "\nEjemplo:\n");
    fprintf(stderr, "  ./bruteforce -e 123456789 input.txt cifrado.des\n");
    fprintf(stderr, "  mpirun -np 4 ./bruteforce cifrado.des test 200000000 0\n");
    fprintf(stderr, "  mpirun -np 4 ./bruteforce cifrado.des test 200000000 1\n");
    return 1;
  }

  // Leer argumentos para bruteforce
  const char *archivo_cifrado = argv[1];
  const char *palabra_clave = argv[2];

  long upper = (1L << 56) - 1;
  if (argc >= 4)
  {
    upper = parse_key(argv[3]);
  }

  int mode = 0;
  if (argc >= 5)
  {
    mode = atoi(argv[4]);
  }

  // Copiar palabra clave
  strncpy(search, palabra_clave, sizeof(search) - 1);
  search[sizeof(search) - 1] = '\0';

  // Leer archivo cifrado
  size_t cipher_len = 0;
  unsigned char *cipher = read_file_all(archivo_cifrado, &cipher_len);
  if (!cipher)
  {
    fprintf(stderr, "Error: No se pudo leer el archivo cifrado '%s'\n", archivo_cifrado);
    return 1;
  }

  int N, id;
  long mylower = 0, myupper = -1;
  MPI_Status st;
  MPI_Request req;
  MPI_Comm comm = MPI_COMM_WORLD;

  MPI_Init(&argc, &argv);
  MPI_Comm_size(comm, &N);
  MPI_Comm_rank(comm, &id);

  // Medir tiempo
  double start_time = 0.0, end_time = 0.0, elapsed_time = 0.0;
  if (id == 0)
  {
    start_time = MPI_Wtime();
    printf("===========================================\n");
    printf("Iniciando búsqueda de llave\n");
    printf("Archivo: %s\n", archivo_cifrado);
    printf("Palabra clave: '%s'\n", palabra_clave);
    printf("Rango de búsqueda: 0 a %ld (inclusive)\n", upper);
    printf("Procesos: %d\n", N);
    printf("Modo de distribución: %s\n", mode == 0 ? "Secuencial" : "Intercalado");
    printf("===========================================\n");
    fflush(stdout);
  }

  long found = 0;

  // Postear recepción no bloqueante de la llave ganadora
  MPI_Irecv(&found, 1, MPI_LONG, MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &req);
  int recv_done = 0;

  // ==================== DISTRIBUCIÓN ====================
  if (mode == 0)
  {
    long range_per_node = (upper + 1) / N; 
    mylower = range_per_node * id;
    myupper = (id == N - 1) ? upper : (range_per_node * (id + 1) - 1);

    for (long i = mylower; i <= myupper && (found == 0); ++i)
    {
      // Revisar si ya llegó la llave desde otro proceso
      if (!recv_done)
      {
        int flag = 0;
        MPI_Test(&req, &flag, &st);
        if (flag && found != 0)
        {
          recv_done = 1;
          break;
        }
      }

      if (tryKey(i, (char *)cipher, (int)cipher_len))
      {
        found = i;
        // Avisar a todos
        for (int node = 0; node < N; ++node)
        {
          MPI_Send(&found, 1, MPI_LONG, node, 0, comm);
        }
        break;
      }
    }
  }
  else
  {
    for (long i = id; i <= upper && (found == 0); i += N)
    {
      if (!recv_done)
      {
        int flag = 0;
        MPI_Test(&req, &flag, &st);
        if (flag && found != 0)
        {
          recv_done = 1;
          break;
        }
      }

      if (tryKey(i, (char *)cipher, (int)cipher_len))
      {
        found = i;
        for (int node = 0; node < N; ++node)
        {
          MPI_Send(&found, 1, MPI_LONG, node, 0, comm);
        }
        break;
      }
    }
  }

  // Asegurar que la recepción no bloqueante termina
  if (!recv_done)
  {
    int flag = 0;
    MPI_Test(&req, &flag, &st);
    if (!flag)
    {
      MPI_Wait(&req, &st);
    }
  }

  // Sincronizar todos
  MPI_Barrier(comm);

  if (id == 0)
  {
    end_time = MPI_Wtime();
    elapsed_time = end_time - start_time;

    // Descifrar y mostrar resultado
    char *result = (char *)malloc(cipher_len + 1);
    if (result)
    {
      memcpy(result, cipher, cipher_len);
      result[cipher_len] = 0;
      decrypt(found, result, (int)cipher_len);

      printf("===========================================\n");
      printf("RESULTADO\n");
      printf("===========================================\n");
      printf("Llave encontrada: %ld\n", found);
      printf("Tiempo transcurrido: %.6f segundos\n", elapsed_time);
      printf("Procesos utilizados: %d\n", N);
      printf("Modo usado: %s\n", mode == 0 ? "Secuencial" : "Intercalado");
      printf("-------------------------------------------\n");
      printf("Texto descifrado:\n%s\n", result);
      printf("===========================================\n");
      fflush(stdout);
      free(result);
    }
  }

  free(cipher);
  MPI_Finalize();
  return 0;
}
