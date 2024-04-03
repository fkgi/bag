package main

import (
	"errors"
	"log"

	"github.com/fkgi/bag"
	"github.com/fkgi/bag/common"
	"github.com/fkgi/diameter"
)

func marHandler(retry bool, avps []diameter.AVP) (bool, []diameter.AVP) {
	var impi string
	var session string
	var e error
	for _, avp := range avps {
		switch avp.Code {
		case 263: // Session-ID
			if len(session) != 0 {
				e = diameter.InvalidAVP{Code: diameter.AvpOccursTooManyTimes, AVP: avp}
			} else {
				session, e = diameter.GetSessionID(avp)
			}
		case 260: // Vendor-Specific-Application-Id
		case 277: // Auth-Session-State
		case 264: // Origin-Host
		case 296: // Origin-Realm
		case 293: // Destination-Host
		case 283: // Destination-Realm
		case 1: // User-Name
			if len(impi) != 0 {
				e = diameter.InvalidAVP{Code: diameter.AvpOccursTooManyTimes, AVP: avp}
			} else {
				impi, e = diameter.GetUserName(avp)
			}
		case 601: // Public-Identity
		case 612: // SIP-Auth-Data-Item
		case 409: // GUSS-Timestamp
		case 284: // Proxy-Info
		case 282: // Route-Record
		default:
			if avp.Mandatory {
				e = diameter.InvalidAVP{Code: diameter.AvpUnsupported, AVP: avp}
			}
		}
		if e != nil {
			break
		}
	}

	result := diameter.Success
	auth := diameter.AVP{}

	if iavp, ok := e.(diameter.InvalidAVP); ok {
		result = iavp.Code
	} else if len(impi) == 0 {
		result = diameter.MissingAvp
		e = diameter.InvalidAVP{Code: result, AVP: diameter.AVP{Code: 1}}
	} else if len(session) == 0 {
		result = diameter.MissingAvp
		e = diameter.InvalidAVP{Code: result, AVP: diameter.SetSessionID("")}
	} else if av := common.QueryDB(impi); len(av.RAND) == 0 {
		result = bag.IdentityUnknown
		e = errors.New("identity not found")
	} else {
		auth = bag.SetSIPAuthDataItem(av.RAND, av.AUTN, nil, av.RES, av.CK, av.IK)
	}

	res := []diameter.AVP{}
	if session != "" {
		res = append(res,
			diameter.SetSessionID(session),
			diameter.SetAuthSessionState(false))
	}
	res = append(res,
		diameter.SetVendorSpecAppID(10415, 16777221),
		diameter.SetResultCode(result),
		diameter.SetOriginHost(diameter.Host),
		diameter.SetOriginRealm(diameter.Realm))

	if result == diameter.Success {
		res = append(res,
			auth,
			diameter.SetUserName(impi))
		if *verbose {
			log.Println("[INFO]", "MAR handling for", impi, "success")
		}
	} else if len(impi) == 0 {
		if *verbose {
			log.Println("[INFO]", "MAR handling fail:", e)
		}
	} else {
		res = append(res,
			diameter.SetUserName(impi))
		if *verbose {
			log.Println("[INFO]", "MAR handling for", impi, "fail:", e)
		}
	}
	return false, res
}
