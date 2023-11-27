package bag

import (
	"github.com/fkgi/diameter"
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
    * [ Line-Identifier ]          ; not supported
    * [AVP]
*/

// SetSIPAuthDataItem make SIP-Auth-Data-Item AVP
func SetSIPAuthDataItem(rand, autn, auts, xres, ck, ik []byte) (a diameter.AVP) {
	v := []diameter.AVP{}
	if len(xres) == 16 {
		a := diameter.AVP{Code: 608, VendorID: 10415, Mandatory: true}
		a.Encode("Digest-AKAv1-MD5")
		v = append(v, a)
	}
	if len(rand) == 16 && len(autn) == 16 {
		a := diameter.AVP{Code: 609, VendorID: 10415, Mandatory: true}
		a.Encode(append(rand, autn...))
		v = append(v, a)
	}
	if len(rand) == 16 && len(auts) == 14 {
		a := diameter.AVP{Code: 610, VendorID: 10415, Mandatory: true}
		a.Encode(append(rand, auts...))
		v = append(v, a)
	} else if len(xres) == 16 {
		a := diameter.AVP{Code: 610, VendorID: 10415, Mandatory: true}
		a.Encode(xres)
		v = append(v, a)
	}
	if len(ck) == 16 {
		a := diameter.AVP{Code: 625, VendorID: 10415, Mandatory: true}
		a.Encode(ck)
		v = append(v, a)
	}
	if len(ik) == 16 {
		a := diameter.AVP{Code: 626, VendorID: 10415, Mandatory: true}
		a.Encode(ik)
		v = append(v, a)
	}
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
		case 609:
			var auth []byte
			if a.VendorID != 10415 || !a.Mandatory {
				e = diameter.InvalidAVP{
					Code: diameter.InvalidAvpBits, AVP: a}
			} else if e = a.Decode(&auth); e != nil {
			} else if len(auth) != 32 {
				e = diameter.InvalidAVP{
					Code: diameter.InvalidAvpValue, AVP: a}
			} else {
				rand = auth[:16]
				autn = auth[16:]
			}
		case 610:
			var auth []byte
			if a.VendorID != 10415 || !a.Mandatory {
				e = diameter.InvalidAVP{
					Code: diameter.InvalidAvpBits, AVP: a}
			} else if e = a.Decode(&auth); e != nil {
			} else if len(auth) == 30 {
				rand = auth[:16]
				auts = auth[16:]
			} else if len(auth) == 16 {
				xres = auth
			} else {
				e = diameter.InvalidAVP{
					Code: diameter.InvalidAvpValue, AVP: a}
			}
		case 625:
			if a.VendorID != 10415 || !a.Mandatory {
				e = diameter.InvalidAVP{
					Code: diameter.InvalidAvpBits, AVP: a}
			} else if e = a.Decode(&ck); e != nil {
			} else if len(ck) != 16 {
				e = diameter.InvalidAVP{
					Code: diameter.InvalidAvpValue, AVP: a}
			}
		case 626:
			if a.VendorID != 10415 || !a.Mandatory {
				e = diameter.InvalidAVP{
					Code: diameter.InvalidAvpBits, AVP: a}
			} else if e = a.Decode(&ik); e != nil {
			} else if len(ik) != 16 {
				e = diameter.InvalidAVP{
					Code: diameter.InvalidAvpValue, AVP: a}
			}
		}
		if e != nil {
			break
		}
	}

	return
}

// GUSS-Timestamp

const IdentityUnknown uint32 = 10415*10000 + 5401
