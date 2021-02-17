#!/usr/bin/env python3
import sys
import numpy as np 
from pickle import load

def main():
    model = load(open("phases-model.pkl", "rb"))
    scaler = load(open("phases-scaler.pkl", "rb"))
    flag = True
    while flag:
        try:
            pmc1, pmc2, pmc3, pmc4, pmc5, cluster = input().split(',') 
            p1 = int(pmc1)
            p2 = int(pmc2)
            p3 = int(pmc3)
            p4 = int(pmc4)
            p5 = int(pmc5)
            cluster = int(cluster)
            pmcs = [[p3, p5, p1, p4, p2, cluster]] # order is based on how the ML was trained

            scaled_pmcs = scaler.transform(pmcs)

            print(model.predict(scaled_pmcs)[0])
            
        except EOFError:
            flag = False

if __name__ == "__main__":
    main()
