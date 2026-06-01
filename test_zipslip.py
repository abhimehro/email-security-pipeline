import tarfile
import io

def test_zipslip():
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tf:
        info = tarfile.TarInfo(name="../../tmp/test.txt")
        info.size = len(b"malicious content")
        tf.addfile(info, io.BytesIO(b"malicious content"))
        
    data.seek(0)
    
    with tarfile.open(fileobj=data, mode="r:*") as tf:
        for member in tf:
            print(f"member.name: {member.name}")
            if member.name.startswith("/") or ".." in member.name:
                print(f"Malicious member name found: {member.name}")

if __name__ == "__main__":
    test_zipslip()
