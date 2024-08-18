private_key = "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1HTUNBUUF3RUFZSEtvWkl6ajBDQVFZRks0RUVBQUVFVERCS0FnRUJCQlVCOG5sbG1pYi9hMTdVdmtVUERZLzYKSC9iRG5RcWhMZ01zQUFRR0k3Nnl3YXBGZ3dxQ0hsY1c0L1pESEVUQUFqNENzUk5nMWZuNmlLYVo2S1JDUTRscgpVdStMMU5FPQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg===="

lines = [private_key[i:i+16].ljust(16) for i in range(0, len(private_key), 16)]
for line in lines:
    print("\"" + line + "\",")
