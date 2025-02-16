package com.slobodanzivanovic.dpmsn.userservice.model.user.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Enum representing various configuration parameters used in the application
 * This enum includes parameters for authentication token expiration times and key values
 */
@Getter
@RequiredArgsConstructor
public enum ConfigurationParameter {

	AUTH_ACCESS_TOKEN_EXPIRE_MINUTE("30"),
	AUTH_REFRESH_TOKEN_EXPIRE_DAY("1"),
	AUTH_PUBLIC_KEY("""
		-----BEGIN PUBLIC KEY-----
		MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsGaPwAOy40l/Ehhuc0hL
		7dxWLbZ/LZS/UlrLkB+a52x9KHeTUDCgTiMy7yNxJHmqkzP+J3QtPkn3jddnXNnq
		TWew99eS4rvFDnqp0caZhO5sCmdUcJaYvlDc//1wJ8WDhs/gW3d/1pTnmDenz9LK
		llHTB+prs5j84EHF4TEIrXEn93YH6e1SxkGfstwtSYIb8Jr1TQXXHME6gz4mQtOJ
		9VeHLOZfnKmvEI9qSEWP30/n7kYlcxVi/3yETWLbRh9to/swS1Gghu0GoaciTYTl
		PsbcoKLkrtS5NDRPfklQRAm1liwFhT6l/jFSst8Xq8CSro6HJkfss93FmYTz6+c/
		sQIDAQAB
		-----END PUBLIC KEY-----
		"""),
	AUTH_PRIVATE_KEY("""
		-----BEGIN PRIVATE KEY-----
		MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCwZo/AA7LjSX8S
		GG5zSEvt3FYttn8tlL9SWsuQH5rnbH0od5NQMKBOIzLvI3EkeaqTM/4ndC0+SfeN
		12dc2epNZ7D315Liu8UOeqnRxpmE7mwKZ1Rwlpi+UNz//XAnxYOGz+Bbd3/WlOeY
		N6fP0sqWUdMH6muzmPzgQcXhMQitcSf3dgfp7VLGQZ+y3C1JghvwmvVNBdccwTqD
		PiZC04n1V4cs5l+cqa8Qj2pIRY/fT+fuRiVzFWL/fIRNYttGH22j+zBLUaCG7Qah
		pyJNhOU+xtygouSu1Lk0NE9+SVBECbWWLAWFPqX+MVKy3xerwJKujocmR+yz3cWZ
		hPPr5z+xAgMBAAECggEAA3ayv45IXsPMgxzyskB1qTZ92gju0gTNMD9IfEx6kgJk
		f2fAVJSX2TZCDkWvt4vMsyDpY89EAiiZUUeCUpA+1FqYXs10p2S7d6TQnSYH+/8N
		z7MmtSKSiON1QMYyWRLnmb05hmJAItpVT9JWm7M5DMmPhLoazPHQk/tb+NIp0vSm
		VM5Nhxri22ewUg3cpj4JnVDXj1DmuTiI4FlCw8gnW/w/cUHscb+Pcnh5rLajToH0
		U3w7TRaYrk67jvB0E2RZtmvJuueRnnFOcoCP0ZokHeS3ObjKH1uZUz6HfLWvmwE8
		z4kHCiVivit/XUA/qTQA9Xf7iPWgrGk52GQWnQBsaQKBgQDZXJEA0X8eUKMDRiWZ
		PbbYjCE931oJd0wXazwkcX7wqyz4bWQrZ9/5acdPqAvg6dw1q88DiiytNmzvFYTE
		dOeWSfn+OmDa7z+AiyeIbQomieE5hSp+eUO+HujLB8qALLNlPU83/fJXY1anZ8eh
		4LuUcF1Mq7jkGNEwJtaSvseoxQKBgQDPwf4PiRRkWHdPH0HC4A6IYwZ06yRziUol
		q4a1lTN7Dn8nXZdqv1BrAqxbPkCka1ZJXXFwXD9CyQMCmZOu76MdQeZgDIEhO/t2
		iuAWpQnFXTtbEi79LID2ie9L+7dZFpsVaD7/On1eC3A7An1u8HQRWLIjtj2suMb4
		h2rF4yTx/QKBgCbOzSDdRpnuAbzS6GGc0CmHk2PNnfC0uQQxZDKJhQWJOmU8erb5
		O9b3GNvTABPvDR8UBsj2AZYHcpmZOPQufy6pFJZca/CK6MaVkcBc34QT9/9iFD0y
		f3LRZ/Tf9jq+QGVh9ePkVkFd/hmzgMQZMMSG71GCE2e+OpMjTAo1P8aVAoGAaUZ6
		7/JdY++0HWLQVuhkVNYg+nQA147VBLujGjZNjOiupAr35D6niGIlZmLoLKi7Y5e3
		GOGVqMjk/pdFz5pcxEGVdExBzs5vQQVkQfVFOz5gCmjvaJj5jHQezxjxMnKTCUj2
		yywfRN109GHxn5q2peeU9SWuoOxM3rj38OiF2x0CgYEAlO7453NQk/z4/YOW9nrN
		Gr0GGatlWMcknjSHiBpn1Lv4TiCX1Ti6AbaOwZp+j3G7kKYf05wscS0l9+qAnvIv
		y12zcV+yfemQNc5OF9IP+1jzWlqRnCL43b6+HFIaoXlwY9YQ2ZmrmV9dC1jqwtSw
		YEpjXG79slLIUz4VN04DhrA=
		-----END PRIVATE KEY-----
		""");

	private final String defaultValue;

}
