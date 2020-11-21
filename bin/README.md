# jwt Basic
### 2020. 11. 18.
### - jwt의 기본 구성
<pre>
    String lowSig = "Encoding된 header" + "Encoding된 payload" + "signiture"

    BASE64(header).
    BASE64(payload).
    BASE64(HS256(lowSig))
</pre>
### 본 프로젝트에선 위와 같이 일일이 인코딩해서 토큰을 생성하지 않고 java jwt 의존성을 사용
### https://mvnrepository.com/artifact/com.auth0/java-jwt