package crypto

func Sign(binPriv []byte, message []byte) ([]byte, error) {
	priv, err := scheme.UnmarshalBinaryPrivateKey(binPriv)
	if err != nil {
		return nil, err
	}
	return scheme.Sign(priv, message, nil), nil
}

func Verify(binPub []byte, message []byte, sig []byte) (bool, error) {
	pub, err := scheme.UnmarshalBinaryPublicKey(binPub)
	if err != nil {
		return false, err
	}

	return scheme.Verify(pub, message, sig, nil), nil
}
