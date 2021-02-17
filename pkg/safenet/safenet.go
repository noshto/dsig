package safenet

import (
	"crypto/x509"
	"fmt"
	"os"
	"runtime"

	"github.com/miekg/pkcs11"
)

var (
	defaultLibPath string
)

func init() {
	switch runtime.GOOS {
	case "windows":
		defaultLibPath = "C:\\Windows\\System32\\eTPKCS11.dll"
	case "darwin":
		defaultLibPath = "/usr/local/lib/libeTPkcs11.dylib"
	case "linux":
		defaultLibPath = "/usr/local/lib/libeTPkcs11.so"
	default:
		fmt.Fprintf(
			os.Stderr,
			"Can't set defaultLibPath as OS is not recognized. "+
				"runtime.GOOS return \"%s\"\n",
			runtime.GOOS,
		)
	}
}

// Config contains properties needed for cnfiguration of the SafeNet library
type Config struct {
	LibPath   string
	UnlockPin string
}

// SafeNet incapsulates necessary primitives needed for digital sign and verify
type SafeNet struct {
	libPath     string
	unlockPin   string
	context     *pkcs11.Ctx
	slots       []uint
	slot        uint
	session     pkcs11.SessionHandle
	initialized bool
	hasSession  bool
	loggedin    bool
}

// Initialize performs necessary actions for preparing to work with safenet dsig token.
func (t *SafeNet) Initialize(config *Config) error {

	var path string
	if len(config.LibPath) == 0 {
		if len(defaultLibPath) == 0 {
			return fmt.Errorf("No libPath provided, nor defaultLibPath was generated")
		}
		path = defaultLibPath
	}

	ctx := pkcs11.New(path)
	if ctx == nil {
		return fmt.Errorf("New call has returned nil")
	}

	t.context = ctx
	t.unlockPin = config.UnlockPin
	t.libPath = config.LibPath

	// Return values: CKR_OK, CKR_HOST_MEMORY
	if err := ctx.Initialize(); err != nil {
		_ = t.Finalize()
		return err
	}

	t.initialized = true

	slot, err := t.getSlot()
	if err != nil {
		_ = t.Finalize()
		return err
	}
	t.slot = slot

	session, err := t.openSession()
	if err != nil {
		_ = t.Finalize()
		return err
	}
	t.session = session
	t.hasSession = true

	err = t.login(pkcs11.CKU_USER)
	if err != nil {
		_ = t.Finalize()
		return err
	}

	t.loggedin = true

	return nil
}

// Finalize performs necessary actions for releasing used resourses.
func (t *SafeNet) Finalize() error {

	defer t.invalidate()

	if t.context == nil {
		return nil
	}

	if t.session != 0 {
		_ = t.context.Logout(t.session)
		_ = t.context.CloseSession(t.session)
	}

	if err := t.context.Finalize(); err != nil {
		return err
	}

	return nil
}

// GetCertificate retrieves value of x.509 certificate
func (t *SafeNet) GetCertificate() (x509.Certificate, error) {
	if !t.isSessionOpened() {
		return x509.Certificate{},
			fmt.Errorf("X509.Certificate method is called before SafeNet being initialized")
	}

	obj, err := t.findObject(
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
			pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		},
	)
	if err != nil {
		return x509.Certificate{}, err
	}

	attributes, err := t.getAttributeValue(
		obj,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, true)},
	)
	if err != nil {
		return x509.Certificate{}, err
	}

	for _, attr := range attributes {
		if attr.Type == pkcs11.CKA_VALUE {
			certificate, err := x509.ParseCertificate(attr.Value)
			if err != nil {
				return x509.Certificate{}, err
			}

			return *certificate, nil
		}
	}

	return x509.Certificate{}, fmt.Errorf("Object not found")
}

// SignPKCS1v15 signs data in a single part, where the signature is an appendix to the data.
// Creates RSASSA-PKCS1-v1_5 signature. Therefore expecting `data` to be valid sha256 hash
func (t *SafeNet) SignPKCS1v15(data []byte) ([]byte, error) {
	if !(t.isInitialized() && t.isSessionOpened()) {
		return []byte{},
			fmt.Errorf("Sign method is called before SafeNet being initialized")
	}

	pKey, err := t.findObject(
		[]*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		},
	)
	if err != nil {
		return []byte{}, err
	}

	// IMPORTANT: https://stackoverflow.com/questions/47106122/sign-sha256-hash-with-rsa-using-pkcs11-api
	// digest should be prefixed with specific bytes, as described in the link above
	prefix := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	payload := make([]byte, len(prefix)+len(data))
	// this is how it is made in example
	copy(payload[0:len(prefix)], prefix)
	copy(payload[len(prefix):], data)

	if err := t.context.SignInit(
		t.session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)},
		pKey,
	); err != nil {
		// Return values: CKR_OK, CKR_FUNCTION_PARALLEL, CKR_FUNCTION_CANCELED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED, CKR_OPERATION_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DATA_INVALID, CKR_HOST_MEMORY, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DEVICE_ERROR
		return []byte{}, err
	}

	if err := t.login(pkcs11.CKU_CONTEXT_SPECIFIC); err != nil {
		return []byte{}, err
	}

	signature, err := t.context.Sign(
		t.session,
		payload,
	)
	if err != nil {
		return []byte{}, err
	}
	return signature, nil
}

func (t *SafeNet) isInitialized() bool {
	return t.initialized
}

func (t *SafeNet) isSessionOpened() bool {
	return t.hasSession
}

func (t *SafeNet) isLoggedIn() bool {
	return t.loggedin
}

func (t *SafeNet) getSlot() (uint, error) {
	if !t.isInitialized() {
		return 0,
			fmt.Errorf("getSlot method is called before SafeNet being initialized")
	}

	slots, err := t.getSlotList()
	if err != nil {
		return 0, err
	}
	t.slots = slots

	var lastErr error
	for _, slot := range t.slots {

		// Lookup slot with signing capability
		info, err := t.context.GetMechanismInfo(
			slot,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)},
		)
		if err != nil {
			lastErr = err
			// Return values: CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_HOST_MEMORY
			continue
		}

		f := pkcs11.CKF_SIGN | pkcs11.CKF_VERIFY | info.Flags
		if info.Flags != f {
			continue
		}

		// Check if the slot with signing capability also capable of generating cert
		info, err = t.context.GetMechanismInfo(
			slot,
			[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, nil)},
		)
		if err != nil {
			lastErr = err
			// Return values: CKR_OK, CKR_SLOT_ID_INVALID, CKR_TOKEN_NOT_PRESENT, CKR_HOST_MEMORY
			continue
		}

		f = pkcs11.CKF_GENERATE_KEY_PAIR | info.Flags
		if info.Flags == f {
			return slot, nil
		}
	}

	return 0, lastErr
}

func (t *SafeNet) getSlotList() ([]uint, error) {
	if !t.isInitialized() {
		return []uint{}, fmt.Errorf("getSlotList method is called before SafeNet being initialized")
	}

	// EXCERPT FROM PKCS#11 9.2 Slot and token management
	// tokenPresent indicates whether the list includes only those slots with a token present (TRUE), or all slots (FALSE)
	tokenPresent := true
	slots, err := t.context.GetSlotList(tokenPresent)
	if err != nil {
		// Return values: CKR_OK, CKR_HOST_MEMORY
		return []uint{}, err
	}

	return slots, nil
}

func (t *SafeNet) openSession() (pkcs11.SessionHandle, error) {
	if !t.isInitialized() {
		return 0, fmt.Errorf("openSession method is called before SafeNet being initialized")
	}

	session, err := t.context.OpenSession(
		t.slot,
		pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION,
	)
	if err != nil {
		// Return values: CKR_OK, CKR_SLOT_ID_INVALID, CKR_FLAGS_INVALID, CKR_SESSION_COUNT, CKR_SESSION_PARALLEL_NOT_SUPPORTED, CKR_TOKEN_WRITE_PROTECTED, CKR_HOST_MEMORY, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DEVICE_ERROR
		return 0, err
	}

	return session, nil
}

func (t *SafeNet) login(userType uint) error {
	if !t.isSessionOpened() {
		return fmt.Errorf("login method is called before SafeNet being initialized")
	}

	if err := t.context.Login(t.session, userType, t.unlockPin); err != nil {
		// Return values: CKR_OK, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_TYPE_INVALID, CKR_PIN_INCORRECT, CKR_HOST_MEMORY, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DEVICE_ERROR
		return err
	}

	return nil
}

func (t *SafeNet) getAttributeValue(obj pkcs11.ObjectHandle, attributes []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	if !t.isLoggedIn() {
		return []*pkcs11.Attribute{},
			fmt.Errorf("getAttributeValue method is called before SafeNet being initialized")
	}
	attributes, err := t.context.GetAttributeValue(
		t.session,
		obj,
		attributes,
	)
	if err != nil {
		// Return values: CKR_OK, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED, CKR_OBJECT_HANDLE_INVALID, CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_SENSITIVE, CKR_HOST_MEMORY, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DEVICE_ERROR
		return []*pkcs11.Attribute{}, err
	}

	return attributes, nil
}

func (t *SafeNet) findObjectFinal() error {
	err := t.context.FindObjectsFinal(t.session)
	if err != nil {
		return err
	}
	return nil
}

func (t *SafeNet) findObject(template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if !t.isLoggedIn() {
		return 0,
			fmt.Errorf("findObject method is called before SafeNet being initialized")
	}

	if err := t.context.FindObjectsInit(
		t.session,
		template,
	); err != nil {
		return 0, err
	}

	defer t.findObjectFinal()

	// EXCERPT FROM PKCS#11 9.4 Object management
	// usMaxObjectCount is the maximum number of object handles to be returned
	usMaxObjectCount := 1
	handles, _, err := t.context.FindObjects(
		t.session,
		usMaxObjectCount,
	)
	if err != nil {
		// Return values: CKR_OK, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_CLOSED, CKR_HOST_MEMORY, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_DEVICE_ERROR
		return 0, err
	}
	if len(handles) == 0 {
		return 0, fmt.Errorf("No object found")
	}

	return handles[0], nil
}

func (t *SafeNet) invalidate() {
	t.slot = 0
	t.session = 0

	t.slots = []uint{}

	t.unlockPin = ""
	t.libPath = ""

	t.hasSession = false
	t.loggedin = false
	t.initialized = false

	if t.context != nil {
		t.context.Destroy()
		t.context = nil
	}
}
