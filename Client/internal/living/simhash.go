package living

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/fnv"
	"html"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type SimHash struct {
	hash hash.Hash
}

func NewSimHash() *SimHash {
	return &SimHash{
		hash: md5.New(),
	}
}

func (s *SimHash) Write(p []byte) (int, error) {
	return s.hash.Write(p)
}

func (s *SimHash) Sum() []byte {
	return s.hash.Sum(nil)
}

func SimHash64(data string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(data))
	return h.Sum64()
}

type Fingerprint struct {
	Vectors []uint64
	Weight  int
}

func ComputeSimHash(text string) uint64 {
	features := extractFeatures(text)

	vectors := make([]int64, 64)

	for _, feature := range features {
		hash := SimHash64(feature)
		for i := 0; i < 64; i++ {
			if (hash>>uint(i))&1 == 1 {
				vectors[i]++
			} else {
				vectors[i]--
			}
		}
	}

	var fingerprint uint64
	for i := 0; i < 64; i++ {
		if vectors[i] > 0 {
			fingerprint |= (1 << uint(i))
		}
	}

	return fingerprint
}

func extractFeatures(text string) []string {
	text = normalizeText(text)

	words := strings.Fields(text)

	var features []string

	for i := 0; i < len(words)-1; i++ {
		features = append(features, words[i]+" "+words[i+1])
	}

	for i := 0; i < len(words)-2; i++ {
		features = append(features, words[i]+" "+words[i+1]+" "+words[i+2])
	}

	re := regexp.MustCompile(`[a-zA-Z0-9]{4,}`)
	matches := re.FindAllString(text, -1)
	features = append(features, matches...)

	return features
}

func normalizeText(text string) string {
	text = html.UnescapeString(text)

	text = strings.ToLower(text)

	re := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	text = re.ReplaceAllString(text, "")

	re = regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	text = re.ReplaceAllString(text, "")

	re = regexp.MustCompile(`<[^>]+>`)
	text = re.ReplaceAllString(text, " ")

	re = regexp.MustCompile(`&#\d+;`)
	text = re.ReplaceAllString(text, " ")

	re = regexp.MustCompile(`\s+`)
	text = re.ReplaceAllString(text, " ")

	text = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		if r > 127 || !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, text)

	return strings.TrimSpace(text)
}

func HammingDistance(hash1, hash2 uint64) int {
	xor := hash1 ^ hash2
	distance := 0

	for xor != 0 {
		distance++
		xor &= (xor - 1)
	}

	return distance
}

func IsSimilar(hash1, hash2 uint64, threshold int) bool {
	return HammingDistance(hash1, hash2) <= threshold
}

func ComputeBodyHash(body string) string {
	normalizedBody := normalizeForHash(body)
	hash := sha256.Sum256([]byte(normalizedBody))
	return fmt.Sprintf("%x", hash)
}

func normalizeForHash(body string) string {
	body = strings.ToLower(body)

	re := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	body = re.ReplaceAllString(body, "")

	re = regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	body = re.ReplaceAllString(body, "")

	re = regexp.MustCompile(`<[^>]+>`)
	body = re.ReplaceAllString(body, " ")

	re = regexp.MustCompile(`\s+`)
	body = re.ReplaceAllString(body, " ")

	body = strings.TrimSpace(body)

	return body
}

type PageSignature struct {
	Hash       string
	SimHash    uint64
	StatusCode int
	Length     int
	MD5        string
	SHA1       string
	SHA256     string
}

func ComputePageSignature(body string, statusCode int) PageSignature {
	normalizedBody := normalizeForHash(body)

	md5Hash := md5.Sum([]byte(normalizedBody))
	sha1Hash := sha1.Sum([]byte(normalizedBody))
	sha256Hash := sha256.Sum256([]byte(normalizedBody))

	return PageSignature{
		Hash:       ComputeBodyHash(body),
		SimHash:    ComputeSimHash(normalizedBody),
		StatusCode: statusCode,
		Length:     len(body),
		MD5:        fmt.Sprintf("%x", md5Hash),
		SHA1:       fmt.Sprintf("%x", sha1Hash),
		SHA256:     fmt.Sprintf("%x", sha256Hash),
	}
}

func HashToUint64(data []byte) uint64 {
	h := fnv.New64a()
	h.Write(data)
	return h.Sum64()
}

func SimHashFromStream(reader io.Reader) (uint64, error) {

	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanWords)

	vectors := make([]int64, 64)

	featureIndex := 0
	for scanner.Scan() {
		word := scanner.Text()
		if len(word) < 3 {
			continue
		}

		hash := HashToUint64([]byte(word))

		for i := 0; i < 64; i++ {
			if (hash>>uint(i))&1 == 1 {
				vectors[i]++
			} else {
				vectors[i]--
			}
		}
		featureIndex++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	if featureIndex == 0 {
		return 0, nil
	}

	var fingerprint uint64
	for i := 0; i < 64; i++ {
		if vectors[i] > 0 {
			fingerprint |= (1 << uint(i))
		}
	}

	return fingerprint, nil
}

func SimHashString(text string) uint64 {
	return ComputeSimHash(text)
}

func IntToBinaryString(n uint64) string {
	result := make([]byte, 64)
	for i := 63; i >= 0; i-- {
		if n&(1<<uint(i)) != 0 {
			result[63-i] = '1'
		} else {
			result[63-i] = '0'
		}
	}
	return string(result)
}

func BinaryStringToUint64(s string) uint64 {
	var result uint64
	for i, c := range s {
		if c == '1' {
			result |= (1 << uint(len(s)-1-i))
		}
	}
	return result
}

func MostSignificantBits(hash1, hash2 uint64, n int) bool {
	mask := ^uint64(0) << (64 - n)
	return (hash1 & mask) == (hash2 & mask)
}

func TopBitsMatch(hash1, hash2 uint64, n int) bool {
	return MostSignificantBits(hash1, hash2, n)
}

type SimHashIndex struct {
	hashes map[uint64][]string
}

func NewSimHashIndex() *SimHashIndex {
	return &SimHashIndex{
		hashes: make(map[uint64][]string),
	}
}

func (idx *SimHashIndex) Add(hash uint64, id string) {
	for i := 0; i < 64; i++ {
		bit := (hash >> uint(i)) & 1
		var neighbor uint64
		if bit == 1 {
			neighbor = hash &^ (1 << uint(i))
		} else {
			neighbor = hash | (1 << uint(i))
		}
		idx.hashes[neighbor] = append(idx.hashes[neighbor], id)
	}
	idx.hashes[hash] = append(idx.hashes[hash], id)
}

func (idx *SimHashIndex) FindSimilar(hash uint64, maxResults int) []string {
	candidates := make(map[string]bool)

	for i := 0; i < 64; i++ {
		bit := (hash >> uint(i)) & 1
		var neighbor uint64
		if bit == 1 {
			neighbor = hash &^ (1 << uint(i))
		} else {
			neighbor = hash | (1 << uint(i))
		}
		for _, id := range idx.hashes[neighbor] {
			candidates[id] = true
		}
	}

	for _, id := range idx.hashes[hash] {
		candidates[id] = true
	}

	var results []string
	count := 0
	for id := range candidates {
		if count >= maxResults {
			break
		}
		results = append(results, id)
		count++
	}

	return results
}

func TrimBytes(b []byte) []byte {
	i := len(b)
	for i > 0 && (b[i-1] == 0 || unicode.IsControl(rune(b[i-1]))) {
		i--
	}
	return b[:i]
}

func MinInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func MaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func Uint64ToBytes(n uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, n)
	return b
}

func BytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

var _ = utf8.RuneCountInString
var _ = io.Discard
var _ = bufio.ScanLines
var _ = TrimBytes
