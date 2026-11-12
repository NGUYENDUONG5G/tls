FROM python:3.14-slim-bookworm@sha256:3fe1a0b6c2d6b2ebb572906cdabeca75aeb558c0c17db5ffefbcf8094871c32b
ARG OPENSSL_VERSION=3.5.5
ARG OPENSSL_SHA256=b28c91532a8b65a1f983b4c28b7488174e4a01008e29ce8e69bd789f28bc2a89
ENV VERSION=${OPENSSL_VERSION} CHECKSUM=${OPENSSL_SHA256}
RUN apt-get update && apt-get install -y --no-install-recommends build-essential perl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /build
RUN python -c 'import urllib.request,hashlib,os; v=os.environ["VERSION"]; u=("https://www.openssl.org/source/old/1.0.2/openssl-"+v+".tar.gz") if v=="1.0.2u" else ("https://github.com/openssl/openssl/releases/download/openssl-"+v+"/openssl-"+v+".tar.gz"); b=urllib.request.urlopen(u,timeout=120).read(); assert hashlib.sha256(b).hexdigest()==os.environ["CHECKSUM"]; open("source.tar.gz","wb").write(b)' 
RUN tar xzf source.tar.gz && cd openssl-${OPENSSL_VERSION} && \
    if [ "$OPENSSL_VERSION" = "1.0.2u" ]; then \
      ./config --prefix=/opt/openssl --openssldir=/opt/openssl/ssl no-shared enable-ssl2 enable-ssl3 enable-weak-ssl-ciphers; \
    else \
      ./config --prefix=/opt/openssl --openssldir=/opt/openssl/ssl no-shared; \
    fi && make -j4
RUN cd openssl-${OPENSSL_VERSION} && \
    if [ "$OPENSSL_VERSION" = "1.0.2u" ]; then \
      make -C test test_evp test_des test_sha test_md5 test_hmac test_rc2 test_rc4 test_rand test_rsa test_bn test_ec test_ecdsa test_ecdh test_dh test_dsa test_ssl test_sslv2conftest; \
    else \
      make test; \
    fi && make install_sw
RUN python -c 'import json,os,subprocess; json.dump({"openssl_version":os.environ["VERSION"],"source_sha256":os.environ["CHECKSUM"],"base":"python:3.14-slim-bookworm@sha256:3fe1a0b6c2d6b2ebb572906cdabeca75aeb558c0c17db5ffefbcf8094871c32b","build_flags":"no-shared; legacy: enable-ssl2 enable-ssl3 enable-weak-ssl-ciphers","upstream_tests":"legacy: explicit crypto and SSL subset (CMS test excluded); modern: full make test","version_a":subprocess.check_output(["/opt/openssl/bin/openssl","version","-a"]).decode()},open("/opt/build-metadata.json","w"),indent=2)'
ENV PATH="/opt/openssl/bin:${PATH}" PYTHONDONTWRITEBYTECODE=1
WORKDIR /work
CMD ["sleep", "infinity"]
