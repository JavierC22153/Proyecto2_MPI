import argparse
import math
import pandas as pd
import matplotlib.pyplot as plt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", help="archivo CSV con columnas: np,trial,elapsed_seconds")
    ap.add_argument("--baseline-np", type=int, default=1, help="np que se usa como base (T1)")
    ap.add_argument("--grafica", default="speedups.png", help="nombre de la imagen de salida")
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    df = df.dropna(subset=["elapsed_seconds"])
    df["elapsed_seconds"] = df["elapsed_seconds"].astype(float)
    df["np"] = df["np"].astype(int)

    # Promedios por np
    g = df.groupby("np")["elapsed_seconds"]
    stats = g.agg(["mean", "std", "count"]).reset_index().rename(columns={"mean":"Tp_mean","std":"Tp_std","count":"n"})
    # T1: promedio para baseline-np
    if args.baseline_np not in set(stats["np"]):
        raise SystemExit(f"No hay datos para baseline np={args.baseline_np}")
    T1 = float(stats.loc[stats["np"]==args.baseline_np, "Tp_mean"].iloc[0])

    stats["speedup"] = T1 / stats["Tp_mean"]
    stats["efficiency"] = stats["speedup"] / stats["np"]

    print("\n=== Resumen ===")
    print(stats.to_string(index=False, float_format=lambda x: f"{x:.4f}"))

    # Gráfica
    plt.figure()
    plt.plot(stats["np"], stats["speedup"], marker="o", label="Speedup")
    plt.plot(stats["np"], stats["np"], linestyle="--", label="Lineal ideal")
    plt.xlabel("Procesos (p)")
    plt.ylabel("Speedup (S)")
    plt.title("Speedup observado vs. ideal")
    plt.legend()
    plt.tight_layout()
    plt.savefig(args.grafica, dpi=160)
    print(f"\nGráfica guardada en: {args.grafica}")

if __name__ == "__main__":
    main()
# Uso  python3 analiza_speedups.py resultados_speedup.csv --baseline-np 1 --grafica speedups.png