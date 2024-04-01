package bag

import (
	"fmt"

	"github.com/fkgi/diameter"
	"github.com/fkgi/diameter/connector"
)

/*
Multimedia-Auth-Request
 <MAR> ::= <Diameter Header: 303, REQ, PXY, 16777221 >
	       < Session-Id >
           { Vendor-Specific-Application-Id }
           { Auth-Session-State } ; NO_STATE_MAINTAINED
           { Origin-Host }        ; Address of BSF
           { Origin-Realm }       ; Realm of BSF
           { Destination-Realm }  ; Realm of HSS
           [ Destination-Host ]   ; Address of the HSS
           [ User-Name ]          ; IMPI from UE
           [ Public-Identity ]    ; IMPU from UE, not supported
           [ SIP-Auth-Data-Item ] ; Authentication Scheme, Synchronization Failure
           [ GUSS-Timestamp ]     ; Timestamp of GUSS in BSF, not supported
          *[ AVP ]
          *[ Proxy-Info ]
          *[ Route-Record ]

Multimedia-Auth-Answer
 <MAR> ::= < Diameter Header: 303, PXY, 16777221 >
           < Session-Id >
           { Vendor-Specific-Application-Id }
           [ Result-Code ]
           [ Experimental-Result]
           { Auth-Session-State }  ; NO_STATE_MAINTAINED
           { Origin-Host }         ; Address of HSS
           { Origin-Realm }        ; Realm of HSS
           [ User-Name ]           ; IMPI, not supported
           [ Public-Identity ]     ; IMPU, not supported
           [ SIP-Auth-Data-Item ]
           [ GBA-UserSecSettings ] ; GUSS, not supported
          *[ AVP ]
          *[ Proxy-Info ]
          *[ Route-Record ]
*/

var marHandler = connector.Handle(303, 16777221, 10415, nil)

func MultimediaAuthRequest(name string, rand, auts []byte) (av AV, e error) {
	reqavp := []diameter.AVP{
		diameter.SetSessionID(diameter.NextSession(diameter.Host.String())),
		diameter.SetAuthSessionState(false),
		diameter.SetVendorSpecAppID(10415, 16777221),
		diameter.SetOriginHost(diameter.Host),
		diameter.SetOriginRealm(diameter.Realm),
		diameter.SetDestinationRealm(diameter.Realm),
		// Destination-Host
		diameter.SetUserName(name),
		// Public-Identity
		// SIP-Auth-Data-Item
		// GUSS-Timestamp
		// Proxy-Info
		// Route-Record
	}
	if len(rand) == 16 && len(auts) == 14 {
		reqavp = append(reqavp, SetSIPAuthDataItem(rand, nil, auts, nil, nil, nil))
	}
	_, avps := marHandler(false, reqavp)

	var result uint32
	for _, a := range avps {
		switch a.Code {
		case 263:
			// Session-Id
		case 260:
			// Vendor-Specific-Application-Id
		case 268, 298:
			// Result-Code
			// Experimental-Result
			result, e = diameter.GetResultCode(a)
		case 277:
			// Auth-Session-State
		case 264:
			// Origin-Host
		case 296:
			// Origin-Realm
		case 1:
			// User-Name
		case 601:
			// Public-Identity
		case 612:
			// SIP-Auth-Data-Item
			av.RAND, av.AUTN, _, av.RES, av.CK, av.IK, e = GetSIPAuthDataItem(a)
		case 400:
			// GBA-UserSecSettings
		case 284:
			// Proxy-Info
		case 282:
			// Route-Record
		}
		if e != nil {
			return
		}
	}

	if result != diameter.Success {
		e = fmt.Errorf("failed result %d from HSS", result)
	} else if len(av.RAND) != 16 {
		e = fmt.Errorf("invalid RAND from HSS")
	} else if len(av.AUTN) != 16 {
		e = fmt.Errorf("invalid AUTN from HSS")
	} else if len(av.RES) == 0 {
		e = fmt.Errorf("invalid XRES from HSS")
	} else if len(av.CK) != 16 {
		e = fmt.Errorf("invalid CK from HSS")
	} else if len(av.IK) != 16 {
		e = fmt.Errorf("invalid IK from HSS")
	}
	return
}

/*
SIP-Auth-Data-Item :: = < AVP Header : 612 10415 >
      [ SIP-Item-Number ]            ; not supported
      [ SIP-Authentication-Scheme ]  ; not supported, only "Digest-AKAv1-MD5"
      [ SIP-Authenticate ]           ; RAND+AUTN, response only
      [ SIP-Authorization ]          ; RAND+AUTS (request) or XRES (response)
      [ SIP-Authentication-Context ] ; not supported
      [ Confidentiality-Key ]        ; CK, response only
      [ Integrity-Key ]              ; IK, response only
      [ SIP-Digest-Authenticate ]    ; not supported
      [ Framed-IP-Address ]          ; not supported
      [ Framed-IPv6-Prefix ]         ; not supported
      [ Framed-Interface-Id ]        ; not supported
    * [ Line-Identifier ]            ; not supported
    * [AVP]
*/

// SetSIPAuthDataItem make SIP-Auth-Data-Item AVP
func SetSIPAuthDataItem(rand, autn, auts, xres, ck, ik []byte) (a diameter.AVP) {
	v := []diameter.AVP{}

	// SIP-Item-Number

	// SIP-Authentication-Scheme
	if len(xres) == 16 {
		a := diameter.AVP{Code: 608, VendorID: 10415, Mandatory: true}
		a.Encode("Digest-AKAv1-MD5")
		v = append(v, a)
	}

	// SIP-Authenticate
	if len(rand) == 16 && len(autn) == 16 {
		a := diameter.AVP{Code: 609, VendorID: 10415, Mandatory: true}
		a.Encode(append(rand, autn...))
		v = append(v, a)
	}

	// SIP-Authorization
	if len(rand) == 16 && len(auts) == 14 {
		a := diameter.AVP{Code: 610, VendorID: 10415, Mandatory: true}
		a.Encode(append(rand, auts...))
		v = append(v, a)
	} else if len(xres) == 16 {
		a := diameter.AVP{Code: 610, VendorID: 10415, Mandatory: true}
		a.Encode(xres)
		v = append(v, a)
	}

	// SIP-Authentication-Context

	// Confidentiality-Key
	if len(ck) == 16 {
		a := diameter.AVP{Code: 625, VendorID: 10415, Mandatory: true}
		a.Encode(ck)
		v = append(v, a)
	}

	// Integrity-Key
	if len(ik) == 16 {
		a := diameter.AVP{Code: 626, VendorID: 10415, Mandatory: true}
		a.Encode(ik)
		v = append(v, a)
	}

	// SIP-Digest-Authenticate
	// Framed-IP-Address
	// Framed-IPv6-Prefix
	// Framed-Interface-Id
	// Line-Identifier

	a = diameter.AVP{Code: 612, VendorID: 10415, Mandatory: true}
	a.Encode(v)
	return
}

// GetSIPAuthDataItem read SIP-Auth-Data-Item AVP
func GetSIPAuthDataItem(a diameter.AVP) (rand, autn, auts, xres, ck, ik []byte, e error) {
	o := []diameter.AVP{}
	if a.VendorID != 10415 || !a.Mandatory {
		e = diameter.InvalidAVP{Code: diameter.InvalidAvpBits, AVP: a}
		return
	}
	if e = a.Decode(&o); e != nil {
		return
	}
	for _, a := range o {
		switch a.Code {
		case 613:
			// SIP-Item-Number
		case 608:
			// SIP-Authentication-Scheme
		case 609:
			// SIP-Authenticate
			var auth []byte
			if a.VendorID != 10415 || !a.Mandatory {
				e = diameter.InvalidAVP{Code: diameter.InvalidAvpBits, AVP: a}
			} else if e = a.Decode(&auth); e != nil {
			} else if len(auth) != 32 {
				e = diameter.InvalidAVP{Code: diameter.InvalidAvpValue, AVP: a}
			} else {
				rand = auth[:16]
				autn = auth[16:]
			}
		case 610:
			// SIP-Authorization
			var auth []byte
			if a.VendorID != 10415 || !a.Mandatory {
				e = diameter.InvalidAVP{Code: diameter.InvalidAvpBits, AVP: a}
			} else if e = a.Decode(&auth); e != nil {
			} else if len(auth) == 30 {
				rand = auth[:16]
				auts = auth[16:]
			} else if len(auth) == 16 {
				xres = auth
			} else {
				e = diameter.InvalidAVP{Code: diameter.InvalidAvpValue, AVP: a}
			}
		case 611:
			// SIP-Authentication-Context
		case 625:
			// Confidentiality-Key
			if a.VendorID != 10415 || !a.Mandatory {
				e = diameter.InvalidAVP{Code: diameter.InvalidAvpBits, AVP: a}
			} else if e = a.Decode(&ck); e != nil {
			} else if len(ck) != 16 {
				e = diameter.InvalidAVP{Code: diameter.InvalidAvpValue, AVP: a}
			}
		case 626:
			// Integrity-Key
			if a.VendorID != 10415 || !a.Mandatory {
				e = diameter.InvalidAVP{Code: diameter.InvalidAvpBits, AVP: a}
			} else if e = a.Decode(&ik); e != nil {
			} else if len(ik) != 16 {
				e = diameter.InvalidAVP{Code: diameter.InvalidAvpValue, AVP: a}
			}
		case 635:
			// SIP-Digest-Authenticate
		case 8:
			// Framed-IP-Address
		case 97:
			// Framed-IPv6-Prefix
		case 96:
			// Framed-Interface-Id
		case 500:
			// Line-Identifier
		}
		if e != nil {
			break
		}
	}
	return
}

// GUSS-Timestamp

// IdentityUnknown Diameter response code
const IdentityUnknown uint32 = 10415*10000 + 5401
