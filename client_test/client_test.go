package client_test

import (
    "testing"

    . "github.com/cs161-staff/project2-starter-code/client"
    userlib "github.com/cs161-staff/project2-userlib"
    "github.com/google/uuid"
    . "github.com/onsi/ginkgo/v2"
    . "github.com/onsi/gomega"
)

func TestClient(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

var _ = Describe("Client Tests", func() {

	BeforeEach(func() {
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("InitUser", func() {
		Specify("should create a new user", func() {
			u, err := InitUser("alice", "password")
			Expect(err).To(BeNil())
			Expect(u).ToNot(BeNil())
		})

		Specify("should error on empty username", func() {
			_, err := InitUser("", "password")
			Expect(err).ToNot(BeNil())
		})

		Specify("should error on duplicate username", func() {
			_, err := InitUser("alice", "password")
			Expect(err).To(BeNil())
			_, err = InitUser("alice", "password")
			Expect(err).ToNot(BeNil())
		})

		Specify("should allow empty password", func() {
			u, err := InitUser("alice", "")
			Expect(err).To(BeNil())
			Expect(u).ToNot(BeNil())
		})

		Specify("should allow two users with the same password", func() {
			_, err := InitUser("alice", "samepassword")
			Expect(err).To(BeNil())
			_, err = InitUser("bob", "samepassword")
			Expect(err).To(BeNil())
		})

		Specify("usernames are case sensitive", func() {
			_, err := InitUser("Alice", "password")
			Expect(err).To(BeNil())
			_, err = InitUser("alice", "password")
			Expect(err).To(BeNil())
		})

		Specify("should support non-alphanumeric usernames", func() {
			u, err := InitUser("us3r!@#", "p@$$w0rd")
			Expect(err).To(BeNil())
			Expect(u).ToNot(BeNil())
		})
	})

	Describe("GetUser", func() {
		Specify("should login with correct credentials", func() {
			InitUser("alice", "password")
			u, err := GetUser("alice", "password")
			Expect(err).To(BeNil())
			Expect(u).ToNot(BeNil())
		})

		Specify("should error on wrong password", func() {
			InitUser("alice", "password")
			_, err := GetUser("alice", "wrongpassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("should error on nonexistent user", func() {
			_, err := GetUser("nobody", "password")
			Expect(err).ToNot(BeNil())
		})

		Specify("should error if UserStruct is tampered with", func() {
			InitUser("alice", "password")
			for k, v := range userlib.DatastoreGetMap() {
				v[0] ^= 0xFF
				userlib.DatastoreSet(k, v)
			}
			_, err := GetUser("alice", "password")
			Expect(err).ToNot(BeNil())
		})

		Specify("should allow login with empty password", func() {
			InitUser("alice", "")
			u, err := GetUser("alice", "")
			Expect(err).To(BeNil())
			Expect(u).ToNot(BeNil())
		})
	})

	Describe("StoreFile and LoadFile", func() {
		Specify("should store and load a file", func() {
			u, _ := InitUser("alice", "password")
			err := u.StoreFile("file.txt", []byte("hello world"))
			Expect(err).To(BeNil())
			content, err := u.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("hello world")))
		})

		Specify("should overwrite an existing file", func() {
			u, _ := InitUser("alice", "password")
			u.StoreFile("file.txt", []byte("original"))
			u.StoreFile("file.txt", []byte("overwritten"))
			content, err := u.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("overwritten")))
		})

		Specify("should support empty file content", func() {
			u, _ := InitUser("alice", "password")
			u.StoreFile("file.txt", []byte{})
			content, err := u.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(len(content)).To(Equal(0))
		})

		Specify("should error loading a file that does not exist", func() {
			u, _ := InitUser("alice", "password")
			_, err := u.LoadFile("nonexistent.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("should support empty filename", func() {
			u, _ := InitUser("alice", "password")
			err := u.StoreFile("", []byte("data"))
			Expect(err).To(BeNil())
			content, err := u.LoadFile("")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("data")))
		})

		Specify("different users can have files with same filename independently", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("alice data"))
			bob.StoreFile("file.txt", []byte("bob data"))
			aliceContent, _ := alice.LoadFile("file.txt")
			bobContent, _ := bob.LoadFile("file.txt")
			Expect(aliceContent).To(Equal([]byte("alice data")))
			Expect(bobContent).To(Equal([]byte("bob data")))
		})

		Specify("should support very large file content", func() {
			alice, _ := InitUser("alice", "password")
			big := make([]byte, 1024*1024)
			for i := range big {
				big[i] = byte(i % 256)
			}
			err := alice.StoreFile("big.txt", big)
			Expect(err).To(BeNil())
			content, err := alice.LoadFile("big.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal(big))
		})

		Specify("second session of same user sees stored file", func() {
			alice1, _ := InitUser("alice", "password")
			alice1.StoreFile("file.txt", []byte("hello"))
			alice2, _ := GetUser("alice", "password")
			content, err := alice2.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("hello")))
		})

		Specify("two sessions of same user see latest file", func() {
			alice1, _ := InitUser("alice", "password")
			alice2, _ := GetUser("alice", "password")
			alice1.StoreFile("file.txt", []byte("from session 1"))
			content, err := alice2.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("from session 1")))
		})
	})

	Describe("Integrity — tampered Datastore", func() {
		Specify("should error if Datastore value is tampered after StoreFile", func() {
			alice, _ := InitUser("alice", "password")
			alice.StoreFile("file.txt", []byte("hello"))
			for k, v := range userlib.DatastoreGetMap() {
				v[0] ^= 0xFF
				userlib.DatastoreSet(k, v)
			}
			_, err := alice.LoadFile("file.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("should error if a chunk is tampered mid-chain", func() {
			alice, _ := InitUser("alice", "password")
			alice.StoreFile("file.txt", []byte("chunk1"))
			alice.AppendToFile("file.txt", []byte("chunk2"))
			alice.AppendToFile("file.txt", []byte("chunk3"))
			for k, v := range userlib.DatastoreGetMap() {
				v[0] ^= 0xFF
				userlib.DatastoreSet(k, v)
			}
			_, err := alice.LoadFile("file.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("should error if invitation is tampered on Datastore", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			blob, _ := userlib.DatastoreGet(invPtr)
			blob[0] ^= 0xFF
			userlib.DatastoreSet(invPtr, blob)
			err := bob.AcceptInvitation("alice", invPtr, "file.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("should error if a value is deleted from Datastore", func() {
			alice, _ := InitUser("alice", "password")
			alice.StoreFile("file.txt", []byte("hello"))
			for k := range userlib.DatastoreGetMap() {
				userlib.DatastoreDelete(k)
			}
			_, err := alice.LoadFile("file.txt")
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("AppendToFile", func() {
		Specify("should append to a file", func() {
			u, _ := InitUser("alice", "password")
			u.StoreFile("file.txt", []byte("hello"))
			err := u.AppendToFile("file.txt", []byte(" world"))
			Expect(err).To(BeNil())
			content, err := u.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("hello world")))
		})

		Specify("should support multiple appends", func() {
			u, _ := InitUser("alice", "password")
			u.StoreFile("file.txt", []byte("a"))
			u.AppendToFile("file.txt", []byte("b"))
			u.AppendToFile("file.txt", []byte("c"))
			content, _ := u.LoadFile("file.txt")
			Expect(content).To(Equal([]byte("abc")))
		})

		Specify("should error appending to nonexistent file", func() {
			u, _ := InitUser("alice", "password")
			err := u.AppendToFile("nonexistent.txt", []byte("data"))
			Expect(err).ToNot(BeNil())
		})

		Specify("append bandwidth should not scale with file size", func() {
			u, _ := InitUser("alice", "password")
			big := make([]byte, 10000)
			u.StoreFile("file.txt", big)
			userlib.DatastoreResetBandwidth()
			u.AppendToFile("file.txt", []byte("small"))
			bw := userlib.DatastoreGetBandwidth()
			Expect(bw).To(BeNumerically("<", 4000))
		})

		Specify("append bandwidth does not scale with number of previous appends", func() {
			alice, _ := InitUser("alice", "password")
			alice.StoreFile("file.txt", []byte("start"))
			for i := 0; i < 100; i++ {
				alice.AppendToFile("file.txt", []byte("x"))
			}
			userlib.DatastoreResetBandwidth()
			alice.AppendToFile("file.txt", []byte("y"))
			bw := userlib.DatastoreGetBandwidth()
			Expect(bw).To(BeNumerically("<", 4000))
		})
	})

	Describe("CreateInvitation and AcceptInvitation", func() {
		Specify("shared user can load the file", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("shared content"))
			invPtr, err := alice.CreateInvitation("file.txt", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invPtr, "bobs-file.txt")
			Expect(err).To(BeNil())
			content, err := bob.LoadFile("bobs-file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("shared content")))
		})

		Specify("shared user sees owner updates", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("v1"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			alice.StoreFile("file.txt", []byte("v2"))
			content, _ := bob.LoadFile("file.txt")
			Expect(content).To(Equal([]byte("v2")))
		})

		Specify("shared user can append and owner sees it", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("hello"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			bob.AppendToFile("file.txt", []byte(" world"))
			content, _ := alice.LoadFile("file.txt")
			Expect(content).To(Equal([]byte("hello world")))
		})

		Specify("non-owner can reshare and recipient can load", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			charlie, _ := InitUser("charlie", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			invPtr2, err := bob.CreateInvitation("file.txt", "charlie")
			Expect(err).To(BeNil())
			err = charlie.AcceptInvitation("bob", invPtr2, "file.txt")
			Expect(err).To(BeNil())
			content, err := charlie.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("data")))
		})

		Specify("should error accepting with wrong sender username", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			InitUser("eve", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			err := bob.AcceptInvitation("eve", invPtr, "file.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("should error if filename already exists in recipient namespace", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("data"))
			bob.StoreFile("file.txt", []byte("bobs own file"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			err := bob.AcceptInvitation("alice", invPtr, "file.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("shared user in new session can load the file", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			bob2, _ := GetUser("bob", "password")
			content, err := bob2.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("data")))
		})

		Specify("owner shares with multiple users independently", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			charlie, _ := InitUser("charlie", "password")
			alice.StoreFile("file.txt", []byte("shared"))
			invB, _ := alice.CreateInvitation("file.txt", "bob")
			invC, _ := alice.CreateInvitation("file.txt", "charlie")
			bob.AcceptInvitation("alice", invB, "file.txt")
			charlie.AcceptInvitation("alice", invC, "file.txt")
			bContent, _ := bob.LoadFile("file.txt")
			cContent, _ := charlie.LoadFile("file.txt")
			Expect(bContent).To(Equal([]byte("shared")))
			Expect(cContent).To(Equal([]byte("shared")))
		})

		Specify("shared user sees update after owner overwrites in new session", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("v1"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			alice2, _ := GetUser("alice", "password")
			alice2.StoreFile("file.txt", []byte("v2"))
			content, err := bob.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("v2")))
		})
	})

	Describe("RevokeAccess", func() {
		Specify("revoked user cannot load the file", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("secret"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			err := alice.RevokeAccess("file.txt", "bob")
			Expect(err).To(BeNil())
			_, err = bob.LoadFile("file.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("non-revoked user still has access", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			charlie, _ := InitUser("charlie", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtrB, _ := alice.CreateInvitation("file.txt", "bob")
			invPtrC, _ := alice.CreateInvitation("file.txt", "charlie")
			bob.AcceptInvitation("alice", invPtrB, "file.txt")
			charlie.AcceptInvitation("alice", invPtrC, "file.txt")
			alice.RevokeAccess("file.txt", "bob")
			content, err := charlie.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("data")))
		})

		Specify("downstream user of revoked user also loses access", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			charlie, _ := InitUser("charlie", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtrB, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtrB, "file.txt")
			invPtrC, _ := bob.CreateInvitation("file.txt", "charlie")
			charlie.AcceptInvitation("bob", invPtrC, "file.txt")
			alice.RevokeAccess("file.txt", "bob")
			_, err := charlie.LoadFile("file.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("owner can still access file after revoking", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			alice.RevokeAccess("file.txt", "bob")
			content, err := alice.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("data")))
		})

		Specify("revoked user cannot append to file", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			alice.RevokeAccess("file.txt", "bob")
			err := bob.AppendToFile("file.txt", []byte("malicious"))
			Expect(err).ToNot(BeNil())
		})

		Specify("revoked user cannot store to file", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			alice.RevokeAccess("file.txt", "bob")
			err := bob.StoreFile("file.txt", []byte("overwrite"))
			Expect(err).ToNot(BeNil())
		})

		Specify("revoked user cannot regain access by calling AcceptInvitation again", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("secret"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			alice.RevokeAccess("file.txt", "bob")
			invPtr2, _ := alice.CreateInvitation("file.txt", "bob")
			err := bob.AcceptInvitation("alice", invPtr2, "file.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("should error revoking a user not directly shared with", func() {
			alice, _ := InitUser("alice", "password")
			InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("data"))
			err := alice.RevokeAccess("file.txt", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("owner revokes then reshares — new recipient can access", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("data"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			alice.RevokeAccess("file.txt", "bob")
			invPtr2, err := alice.CreateInvitation("file.txt", "bob")
			Expect(err).To(BeNil())
			err = bob.AcceptInvitation("alice", invPtr2, "file-new.txt")
			Expect(err).To(BeNil())
			content, err := bob.LoadFile("file-new.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("data")))
		})

		Specify("revoked user with cached pool cannot read after revocation", func() {
			alice, _ := InitUser("alice", "password")
			bob, _ := InitUser("bob", "password")
			alice.StoreFile("file.txt", []byte("secret"))
			invPtr, _ := alice.CreateInvitation("file.txt", "bob")
			bob.AcceptInvitation("alice", invPtr, "file.txt")
			content, err := bob.LoadFile("file.txt")
			Expect(err).To(BeNil())
			Expect(content).To(Equal([]byte("secret")))
			alice.RevokeAccess("file.txt", "bob")
			_, err = bob.LoadFile("file.txt")
			Expect(err).ToNot(BeNil())
		})
	})
})

var _ uuid.UUID