package common

type MeReq struct {
	Method     string
	RequestURI string
	IMPI       string
	IMPU       string
	Body       []byte
	RAND       []byte
	AUTN       []byte
	RES        []byte
	IK         []byte
	CK         []byte
	ClearCache bool
}

type MeAns struct {
	Code int
	Body []byte
}
