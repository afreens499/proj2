package client

import (
	"encoding/json"
	"errors"

	"github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"
)


type User struct {
	Username         string
	PKEDecKey        userlib.PKEDecKey
	DSSignKey        userlib.DSSignKey
	OwnedFilesMap    map[string]PoolEntry
	NonOwnedFilesMap map[string]PoolEntry
	SharedFilesMap   map[string]map[string]PoolEntry
	EncKey           []byte `json:"-"`
	MACKey           []byte `json:"-"`
}

type PoolEntry struct {
	PoolUUID   uuid.UUID
	PoolEncKey []byte
	PoolMACKey []byte
}

type PoolStruct struct {
	FileHeaderUUID uuid.UUID
	FileEncKey     []byte
	FileMACKey     []byte
}

type FileHeaderStruct struct {
	FirstChunkUUID uuid.UUID
	EndChunkUUID   uuid.UUID
}

type FileChunkStruct struct {
	Data          []byte
	NextChunkUUID uuid.UUID
}

type InvitationStruct struct {
	PoolUUID   uuid.UUID
	PoolEncKey []byte
	PoolMACKey []byte
}

type invitationEnvelope struct {
	EncryptedKey []byte
	Ciphertext   []byte
	MAC          []byte
	Sig          []byte
}


func seal(encKey []byte, macKey []byte, v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	iv := userlib.RandomBytes(16)
	ct := userlib.SymEnc(encKey, iv, data)
	mac, err := userlib.HMACEval(macKey, ct)
	if err != nil {
		return nil, err
	}
	return append(ct, mac...), nil
}

func unseal(encKey []byte, macKey []byte, blob []byte, dst interface{}) error {
	if len(blob) < 64 {
		return errors.New("blob too short")
	}
	ct := blob[:len(blob)-64]
	mac := blob[len(blob)-64:]
	expected, err := userlib.HMACEval(macKey, ct)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(expected, mac) {
		return errors.New("HMAC verification failed")
	}
	plain := userlib.SymDec(encKey, ct)
	return json.Unmarshal(plain, dst)
}

func deriveUserKeys(username string, password string) (encKey []byte, macKey []byte, err error) {
	salt := userlib.Hash([]byte(username))[:16]
	rootKey := userlib.Argon2Key([]byte(password), salt, 16)
	encKey, err = userlib.HashKDF(rootKey, []byte("user-enc"))
	if err != nil {
		return nil, nil, err
	}
	encKey = encKey[:16]
	macKey, err = userlib.HashKDF(rootKey, []byte("user-mac"))
	if err != nil {
		return nil, nil, err
	}
	macKey = macKey[:16]
	return encKey, macKey, nil
}

func userUUID(username string) (uuid.UUID, error) {
	return uuid.FromBytes(userlib.Hash([]byte(username))[:16])
}

func (u *User) saveUser() error {
	if u.EncKey == nil || u.MACKey == nil {
		return errors.New("user keys not set in memory")
	}
	blob, err := seal(u.EncKey, u.MACKey, u)
	if err != nil {
		return err
	}
	uid, err := userUUID(u.Username)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(uid, blob)
	return nil
}

func reloadUser(u *User) (*User, error) {
	uid, err := userUUID(u.Username)
	if err != nil {
		return nil, err
	}
	blob, ok := userlib.DatastoreGet(uid)
	if !ok {
		return nil, errors.New("user not found on reload")
	}
	var fresh User
	err = unseal(u.EncKey, u.MACKey, blob, &fresh)
	if err != nil {
		return nil, err
	}
	fresh.EncKey = u.EncKey
	fresh.MACKey = u.MACKey
	return &fresh, nil
}

func loadPool(entry PoolEntry) (PoolStruct, error) {
	var pool PoolStruct
	blob, ok := userlib.DatastoreGet(entry.PoolUUID)
	if !ok {
		return pool, errors.New("pool not found: access may have been revoked")
	}
	err := unseal(entry.PoolEncKey, entry.PoolMACKey, blob, &pool)
	return pool, err
}

func savePool(pool PoolStruct) (PoolEntry, error) {
	poolEncKey := userlib.RandomBytes(16)
	poolMACKey := userlib.RandomBytes(16)
	poolUUID := uuid.New()
	blob, err := seal(poolEncKey, poolMACKey, pool)
	if err != nil {
		return PoolEntry{}, err
	}
	userlib.DatastoreSet(poolUUID, blob)
	return PoolEntry{PoolUUID: poolUUID, PoolEncKey: poolEncKey, PoolMACKey: poolMACKey}, nil
}

func updatePool(entry PoolEntry, pool PoolStruct) error {
	blob, err := seal(entry.PoolEncKey, entry.PoolMACKey, pool)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(entry.PoolUUID, blob)
	return nil
}

func loadFileHeader(pool PoolStruct) (FileHeaderStruct, error) {
	var header FileHeaderStruct
	blob, ok := userlib.DatastoreGet(pool.FileHeaderUUID)
	if !ok {
		return header, errors.New("file header not found")
	}
	err := unseal(pool.FileEncKey, pool.FileMACKey, blob, &header)
	return header, err
}

func saveFileHeader(pool PoolStruct, header FileHeaderStruct) error {
	blob, err := seal(pool.FileEncKey, pool.FileMACKey, header)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(pool.FileHeaderUUID, blob)
	return nil
}

func loadChunk(pool PoolStruct, chunkUUID uuid.UUID) (FileChunkStruct, error) {
	var chunk FileChunkStruct
	blob, ok := userlib.DatastoreGet(chunkUUID)
	if !ok {
		return chunk, errors.New("chunk not found")
	}
	err := unseal(pool.FileEncKey, pool.FileMACKey, blob, &chunk)
	return chunk, err
}

func saveChunk(pool PoolStruct, chunkUUID uuid.UUID, chunk FileChunkStruct) error {
	blob, err := seal(pool.FileEncKey, pool.FileMACKey, chunk)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(chunkUUID, blob)
	return nil
}

func resolvePool(u *User, filename string) (PoolStruct, PoolEntry, error) {
	entry, ok := u.OwnedFilesMap[filename]
	if !ok {
		entry, ok = u.NonOwnedFilesMap[filename]
		if !ok {
			return PoolStruct{}, PoolEntry{}, errors.New("file not found in namespace")
		}
	}
	pool, err := loadPool(entry)
	return pool, entry, err
}


func InitUser(username string, password string) (userdataptr *User, err error) {
	if username == "" {
		return nil, errors.New("username cannot be empty")
	}

	uid, err := userUUID(username)
	if err != nil {
		return nil, err
	}
	_, exists := userlib.DatastoreGet(uid)
	if exists {
		return nil, errors.New("user already exists")
	}

	pkeEncKey, pkeDecKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, err
	}
	dsSignKey, dsVerifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return nil, err
	}

	err = userlib.KeystoreSet("enc:"+username, pkeEncKey)
	if err != nil {
		return nil, err
	}
	err = userlib.KeystoreSet("sig:"+username, dsVerifyKey)
	if err != nil {
		return nil, err
	}

	encKey, macKey, err := deriveUserKeys(username, password)
	if err != nil {
		return nil, err
	}

	u := &User{
		Username:         username,
		PKEDecKey:        pkeDecKey,
		DSSignKey:        dsSignKey,
		OwnedFilesMap:    make(map[string]PoolEntry),
		NonOwnedFilesMap: make(map[string]PoolEntry),
		SharedFilesMap:   make(map[string]map[string]PoolEntry),
		EncKey:           encKey,
		MACKey:           macKey,
	}

	err = u.saveUser()
	if err != nil {
		return nil, err
	}
	return u, nil
}


func GetUser(username string, password string) (userdataptr *User, err error) {
	uid, err := userUUID(username)
	if err != nil {
		return nil, err
	}

	blob, ok := userlib.DatastoreGet(uid)
	if !ok {
		return nil, errors.New("user does not exist")
	}

	encKey, macKey, err := deriveUserKeys(username, password)
	if err != nil {
		return nil, err
	}

	var u User
	err = unseal(encKey, macKey, blob, &u)
	if err != nil {
		return nil, errors.New("invalid credentials or UserStruct tampered with")
	}

	u.EncKey = encKey
	u.MACKey = macKey

	return &u, nil
}

func (u *User) StoreFile(filename string, content []byte) (err error) {

	fresh, ferr := reloadUser(u)
	if ferr == nil {
		u.OwnedFilesMap = fresh.OwnedFilesMap
		u.NonOwnedFilesMap = fresh.NonOwnedFilesMap
		u.SharedFilesMap = fresh.SharedFilesMap
	}

	existingEntry, ownedOk := u.OwnedFilesMap[filename]
	nonOwnedEntry, nonOwnedOk := u.NonOwnedFilesMap[filename]

	var pool PoolStruct
	var entry PoolEntry

	if !ownedOk && !nonOwnedOk {
		fileEncKey := userlib.RandomBytes(16)
		fileMACKey := userlib.RandomBytes(16)
		fileHeaderUUID := uuid.New()

		pool = PoolStruct{
			FileHeaderUUID: fileHeaderUUID,
			FileEncKey:     fileEncKey,
			FileMACKey:     fileMACKey,
		}
		entry, err = savePool(pool)
		if err != nil {
			return err
		}
		u.OwnedFilesMap[filename] = entry
		u.SharedFilesMap[filename] = make(map[string]PoolEntry)
	} else if ownedOk {
		entry = existingEntry
		pool, err = loadPool(entry)
		if err != nil {
			return err
		}
	} else {
		entry = nonOwnedEntry
		pool, err = loadPool(entry)
		if err != nil {
			return err
		}
	}

	firstChunkUUID := uuid.New()
	endChunkUUID := uuid.New()

	chunk := FileChunkStruct{
		Data:          content,
		NextChunkUUID: endChunkUUID,
	}
	err = saveChunk(pool, firstChunkUUID, chunk)
	if err != nil {
		return err
	}

	header := FileHeaderStruct{
		FirstChunkUUID: firstChunkUUID,
		EndChunkUUID:   endChunkUUID,
	}
	err = saveFileHeader(pool, header)
	if err != nil {
		return err
	}

	return u.saveUser()
}



func (u *User) LoadFile(filename string) (content []byte, err error) {

	fresh, ferr := reloadUser(u)
	if ferr == nil {
		u.OwnedFilesMap = fresh.OwnedFilesMap
		u.NonOwnedFilesMap = fresh.NonOwnedFilesMap
		u.SharedFilesMap = fresh.SharedFilesMap
	}

	pool, _, err := resolvePool(u, filename)
	if err != nil {
		return nil, err
	}

	header, err := loadFileHeader(pool)
	if err != nil {
		return nil, err
	}

	var result []byte
	currentUUID := header.FirstChunkUUID
	for currentUUID != header.EndChunkUUID {
		chunk, err := loadChunk(pool, currentUUID)
		if err != nil {
			return nil, err
		}
		result = append(result, chunk.Data...)
		currentUUID = chunk.NextChunkUUID
	}

	if result == nil {
		result = []byte{}
	}
	return result, nil
}


func (u *User) AppendToFile(filename string, content []byte) error {
	pool, _, err := resolvePool(u, filename)
	if err != nil {
		return err
	}

	header, err := loadFileHeader(pool)
	if err != nil {
		return err
	}

	newEndUUID := uuid.New()
	chunk := FileChunkStruct{
		Data:          content,
		NextChunkUUID: newEndUUID,
	}
	err = saveChunk(pool, header.EndChunkUUID, chunk)
	if err != nil {
		return err
	}

	header.EndChunkUUID = newEndUUID
	return saveFileHeader(pool, header)
}


func (u *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {

	fresh, ferr := reloadUser(u)
	if ferr == nil {
		u.OwnedFilesMap = fresh.OwnedFilesMap
		u.NonOwnedFilesMap = fresh.NonOwnedFilesMap
		u.SharedFilesMap = fresh.SharedFilesMap
	}

	recipientEncKey, ok := userlib.KeystoreGet("enc:" + recipientUsername)
	if !ok {
		return uuid.Nil, errors.New("recipient does not exist")
	}

	ownedEntry, ownedOk := u.OwnedFilesMap[filename]
	nonOwnedEntry, nonOwnedOk := u.NonOwnedFilesMap[filename]

	if !ownedOk && !nonOwnedOk {
		return uuid.Nil, errors.New("file not found in namespace")
	}

	var invEntry PoolEntry
	if ownedOk {
		pool, err := loadPool(ownedEntry)
		if err != nil {
			return uuid.Nil, err
		}
		newPool := PoolStruct{
			FileHeaderUUID: pool.FileHeaderUUID,
			FileEncKey:     pool.FileEncKey,
			FileMACKey:     pool.FileMACKey,
		}
		recipientEntry, err := savePool(newPool)
		if err != nil {
			return uuid.Nil, err
		}
		if u.SharedFilesMap[filename] == nil {
			u.SharedFilesMap[filename] = make(map[string]PoolEntry)
		}
		u.SharedFilesMap[filename][recipientUsername] = recipientEntry
		invEntry = recipientEntry

		if err := u.saveUser(); err != nil {
			return uuid.Nil, err
		}
	} else {
		invEntry = nonOwnedEntry
	}

	inv := InvitationStruct{
		PoolUUID:   invEntry.PoolUUID,
		PoolEncKey: invEntry.PoolEncKey,
		PoolMACKey: invEntry.PoolMACKey,
	}

	invBytes, err := json.Marshal(inv)
	if err != nil {
		return uuid.Nil, err
	}

	symEncKey := userlib.RandomBytes(16)
	symMACKey := userlib.RandomBytes(16)
	symKeys := append(symEncKey, symMACKey...)

	encryptedKeys, err := userlib.PKEEnc(recipientEncKey, symKeys)
	if err != nil {
		return uuid.Nil, err
	}

	iv := userlib.RandomBytes(16)
	ciphertext := userlib.SymEnc(symEncKey, iv, invBytes)
	mac, err := userlib.HMACEval(symMACKey, ciphertext)
	if err != nil {
		return uuid.Nil, err
	}

	sigPayload := append(ciphertext, mac...)
	sig, err := userlib.DSSign(u.DSSignKey, sigPayload)
	if err != nil {
		return uuid.Nil, err
	}

	envelope := invitationEnvelope{
		EncryptedKey: encryptedKeys,
		Ciphertext:   ciphertext,
		MAC:          mac,
		Sig:          sig,
	}

	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		return uuid.Nil, err
	}

	invitationPtr = uuid.New()
	userlib.DatastoreSet(invitationPtr, envelopeBytes)

	return invitationPtr, nil
}

func (u *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	fresh, ferr := reloadUser(u)
	if ferr == nil {
		u.OwnedFilesMap = fresh.OwnedFilesMap
		u.NonOwnedFilesMap = fresh.NonOwnedFilesMap
		u.SharedFilesMap = fresh.SharedFilesMap
	}

	if _, ok := u.OwnedFilesMap[filename]; ok {
		return errors.New("filename already exists in personal namespace")
	}
	if _, ok := u.NonOwnedFilesMap[filename]; ok {
		return errors.New("filename already exists in personal namespace")
	}

	stored, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation not found or already deleted")
	}

	var envelope invitationEnvelope
	err := json.Unmarshal(stored, &envelope)
	if err != nil {
		return errors.New("invitation blob malformed")
	}

	senderVerifyKey, ok := userlib.KeystoreGet("sig:" + senderUsername)
	if !ok {
		return errors.New("sender does not exist")
	}
	sigPayload := append(envelope.Ciphertext, envelope.MAC...)
	err = userlib.DSVerify(senderVerifyKey, sigPayload, envelope.Sig)
	if err != nil {
		return errors.New("invitation signature verification failed")
	}

	symKeys, err := userlib.PKEDec(u.PKEDecKey, envelope.EncryptedKey)
	if err != nil {
		return errors.New("failed to decrypt invitation keys")
	}
	if len(symKeys) != 32 {
		return errors.New("invalid sym key length in invitation")
	}
	symEncKey := symKeys[:16]
	symMACKey := symKeys[16:]

	expectedMAC, err := userlib.HMACEval(symMACKey, envelope.Ciphertext)
	if err != nil {
		return err
	}
	if !userlib.HMACEqual(expectedMAC, envelope.MAC) {
		return errors.New("invitation MAC verification failed")
	}

	invBytes := userlib.SymDec(symEncKey, envelope.Ciphertext)
	var inv InvitationStruct
	err = json.Unmarshal(invBytes, &inv)
	if err != nil {
		return errors.New("failed to unmarshal invitation")
	}

	_, poolExists := userlib.DatastoreGet(inv.PoolUUID)
	if !poolExists {
		return errors.New("invitation is no longer valid: access has been revoked")
	}

	u.NonOwnedFilesMap[filename] = PoolEntry{
		PoolUUID:   inv.PoolUUID,
		PoolEncKey: inv.PoolEncKey,
		PoolMACKey: inv.PoolMACKey,
	}

	userlib.DatastoreDelete(invitationPtr)

	return u.saveUser()
}


func (u *User) RevokeAccess(filename string, recipientUsername string) error {
	fresh, ferr := reloadUser(u)
	if ferr == nil {
		u.OwnedFilesMap = fresh.OwnedFilesMap
		u.NonOwnedFilesMap = fresh.NonOwnedFilesMap
		u.SharedFilesMap = fresh.SharedFilesMap
	}

	ownedEntry, ok := u.OwnedFilesMap[filename]
	if !ok {
		return errors.New("file not found in owned files")
	}

	recipients, ok := u.SharedFilesMap[filename]
	if !ok || len(recipients) == 0 {
		return errors.New("file has no sharing records")
	}
	_, ok = recipients[recipientUsername]
	if !ok {
		return errors.New("recipient was not directly shared with")
	}

	pool, err := loadPool(ownedEntry)
	if err != nil {
		return err
	}

	header, err := loadFileHeader(pool)
	if err != nil {
		return err
	}

	var chunks [][]byte
	currentUUID := header.FirstChunkUUID
	for currentUUID != header.EndChunkUUID {
		chunk, err := loadChunk(pool, currentUUID)
		if err != nil {
			return err
		}
		chunks = append(chunks, chunk.Data)
		currentUUID = chunk.NextChunkUUID
	}

	newFileEncKey := userlib.RandomBytes(16)
	newFileMACKey := userlib.RandomBytes(16)
	pool.FileEncKey = newFileEncKey
	pool.FileMACKey = newFileMACKey

	if len(chunks) == 0 {
		chunks = append(chunks, []byte{})
	}
	chunkUUIDs := make([]uuid.UUID, len(chunks))
	for i := range chunkUUIDs {
		chunkUUIDs[i] = uuid.New()
	}
	newEndUUID := uuid.New()

	for i, data := range chunks {
		nextUUID := newEndUUID
		if i+1 < len(chunks) {
			nextUUID = chunkUUIDs[i+1]
		}
		err = saveChunk(pool, chunkUUIDs[i], FileChunkStruct{Data: data, NextChunkUUID: nextUUID})
		if err != nil {
			return err
		}
	}

	newHeader := FileHeaderStruct{
		FirstChunkUUID: chunkUUIDs[0],
		EndChunkUUID:   newEndUUID,
	}
	err = saveFileHeader(pool, newHeader)
	if err != nil {
		return err
	}

	err = updatePool(ownedEntry, pool)
	if err != nil {
		return err
	}

	for recipient, recipientEntry := range recipients {
		if recipient == recipientUsername {
			continue
		}
		recipientPool, err := loadPool(recipientEntry)
		if err != nil {
			continue
		}
		recipientPool.FileEncKey = newFileEncKey
		recipientPool.FileMACKey = newFileMACKey
		err = updatePool(recipientEntry, recipientPool)
		if err != nil {
			return err
		}
	}

	userlib.DatastoreDelete(recipients[recipientUsername].PoolUUID)
	delete(u.SharedFilesMap[filename], recipientUsername)

	return u.saveUser()
}