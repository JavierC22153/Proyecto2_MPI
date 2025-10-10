#!/usr/bin/env bash
set -euo pipefail

# Uso:
#   chmod +x experimentos.sh
#   ./experimentos.sh ./bruteforce output.des CLAVE 4 10 1
#
# Parámetros:
#   $1: binario (ruta a ./bruteforce ya compilado)
#   $2: archivo .des cifrado
#   $3: palabra clave
#   $4: procesos ini (ej. 2)
#   $5: repeticiones por punto (ej. 10)
#   $6: modo (sequential|interleaved)  [alias de 0|1]
#   $7: llave_max (opcional, por ejemplo 200000000)

BIN="${1:-./bruteforce}"
CIF="${2:-cifrado.des}"
KEYWORD="${3:-test}"
NP_START="${4:-2}"
REPS="${5:-5}"
MODE_IN="${6:-interleaved}"
UPPER="${7:-}"

if [[ "${MODE_IN}" == "sequential" ]]; then MODE=0; else MODE=1; fi

out="resultados_speedup.csv"
echo "np,trial,elapsed_seconds" > "$out"

for NP in $(seq ${NP_START} 1 $((NP_START+4))); do
  for r in $(seq 1 ${REPS}); do
    if [[ -n "${UPPER}" ]]; then
      t=$(mpirun -np ${NP} "${BIN}" "${CIF}" "${KEYWORD}" "${UPPER}" "${MODE}" | awk '/Tiempo transcurrido/ {print $3}')
    else
      t=$(mpirun -np ${NP} "${BIN}" "${CIF}" "${KEYWORD}" "${MODE}" | awk '/Tiempo transcurrido/ {print $3}')
    fi
    echo "${NP},${r},${t}" >> "$out"
    echo "NP=${NP} rep=${r} t=${t}s"
  done
done

echo "Listo -> ${out}"
