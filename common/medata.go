package common

type MeReq struct {
	Method     string
	RequestURI string
	IMPI       string
	IMPU       string
	Body       []byte
}

type MeAns struct {
	Code int
	Body []byte
}
