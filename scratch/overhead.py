CAP = 51652                                  # bytes, 20 s clip (one figure everywhere)
for name, ct in (("512", 768), ("768", 1088), ("1024", 1568)):
    header = 4 + 1 + 1 + 1 + ct + 4
    fixed = header + 16 + 32                 # + IV + tag
    print(f"ML-KEM-{name}: header={header} B, header+IV+tag={fixed} B "
          f"(+1..16 B padding) = {100*fixed/CAP:.2f}% of capacity")
