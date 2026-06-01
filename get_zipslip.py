import tarfile
import io

def test():
    data = b"some data"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
        if hasattr(tarfile, 'data_filter'):
            tf.extraction_filter = getattr(tarfile, 'data_filter')
