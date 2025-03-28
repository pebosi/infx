package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/rakyll/magicmime"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type MediaMetadata struct {
	FileName                string                 `json:"file_name"`
	MimeType                string                 `json:"mime_type"`
	FileExt                 string                 `json:"file_extension"`
	FileSize                int64                  `json:"file_size"`
	FileSizeHuman           string                 `json:"file_size_human"`
	Duration                string                 `json:"duration"`
	MediaIsAnimation        bool                   `json:"media_is_animation"`
	MediaIsEncrypted        bool                   `json:"media_is_encrypted"`
	MediaVideoWithAudioOnly bool                   `json:"media_video_with_audio_only"`
	Hashes                  map[string]string      `json:"hashes"`
	EXIF                    map[string]interface{} `json:"exif"`
	Media                   map[string]interface{} `json:"media"`
}

func runCommand(tool string, args ...string) ([]byte, error) {
	cmd := exec.Command(tool, args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s error: %w", tool, err)
	}
	return output, nil
}

func getExifData(filePath string) (map[string]interface{}, error) {
	out, err := runCommand("exiftool", "-j", filePath)
	if err != nil {
		return nil, err
	}
	var data []map[string]interface{}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("failed to parse exiftool output: %w", err)
	}
	if len(data) > 0 {
		return data[0], nil
	}
	return nil, fmt.Errorf("no EXIF data found")
}

func getMediaInfo(filePath string) (map[string]interface{}, error) {
	out, err := runCommand("mediainfo", "--Output=JSON", filePath)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	if err := json.Unmarshal(out, &data); err != nil {
		return nil, fmt.Errorf("failed to parse mediainfo output: %w", err)
	}
	return data, nil
}

func extractDuration(exif, media map[string]interface{}) string {
	if val, ok := exif["Duration"]; ok {
		return fmt.Sprintf("%v", val)
	}
	if media["media"] != nil {
		if mediaMap, ok := media["media"].(map[string]interface{}); ok {
			if tracks, ok := mediaMap["track"].([]interface{}); ok {
				for _, track := range tracks {
					if trackMap, ok := track.(map[string]interface{}); ok {
						if trackMap["@type"] == "Video" {
							if duration, ok := trackMap["Duration"]; ok {
								return fmt.Sprintf("%v", duration)
							}
						}
					}
				}
			}
		}
	}
	return "Unknown"
}

func isAnimation(mimeType string, exif, media map[string]interface{}) bool {
	isGIF := mimeType == "image/gif"
	isWebP := mimeType == "image/webp"

	// EXIF checks
	if fc, ok := exif["FrameCount"]; ok {
		if count, ok := fc.(float64); ok && count > 1 {
			return true
		}
	}
	if anim, ok := exif["Animation"]; ok {
		if val, ok := anim.(string); ok && (val == "Yes" || val == "True") {
			return true
		}
	}
	if dur, ok := exif["Duration"]; ok {
		if d, ok := dur.(float64); ok && d > 0 {
			return true
		}
	}

	// MediaInfo checks
	mediaRoot, ok := media["media"].(map[string]interface{})
	if !ok {
		return false
	}
	tracks, ok := mediaRoot["track"].([]interface{})
	if !ok {
		return false
	}

	for _, t := range tracks {
		if track, ok := t.(map[string]interface{}); ok {
			format, _ := track["Format"].(string)

			// Check only relevant formats
			if (isGIF && strings.Contains(format, "GIF")) || (isWebP && strings.Contains(format, "WebP")) {
				if fc, ok := track["FrameCount"].(string); ok && fc != "1" {
					return true
				}
				if dur, ok := track["Duration"].(string); ok && dur != "0" {
					return true
				}
			}
		}
	}
	return false
}

func isEncrypted(media map[string]interface{}) bool {
	mediaRoot, ok := media["media"].(map[string]interface{})
	if !ok {
		return false
	}

	tracks, ok := mediaRoot["track"].([]interface{})
	if !ok {
		return false
	}

	for _, t := range tracks {
		if trackMap, ok := t.(map[string]interface{}); ok {
			if encVal, exists := trackMap["Encryption"]; exists {
				if encStr, ok := encVal.(string); ok && strings.EqualFold(encStr, "Encrypted") {
					return true
				}
			}
		}
	}
	return false
}

func isVideoWithAudioOnly(mimeType string, exif map[string]interface{}, media map[string]interface{}) bool {
	if !strings.HasPrefix(mimeType, "video/") {
		return false
	}

	hasVideoTrack := false
	hasGeneralVideoCount := false

	// Check MediaInfo video track
	if mediaRoot, ok := media["media"].(map[string]interface{}); ok {
		if tracks, ok := mediaRoot["track"].([]interface{}); ok {
			for _, t := range tracks {
				if trackMap, ok := t.(map[string]interface{}); ok {
					// Any track explicitly marked as video?
					if tType, ok := trackMap["@type"].(string); ok && tType == "Video" {
						hasVideoTrack = true
					}

					// General track with VideoCount > 0?
					if tType, ok := trackMap["@type"].(string); ok && tType == "General" {
						if vc, ok := trackMap["VideoCount"].(string); ok {
							if vCount, err := strconv.Atoi(vc); err == nil && vCount > 0 {
								hasGeneralVideoCount = true
							}
						}
					}
				}
			}
		}
	}

	hasVideoExifKey := false
	for _, key := range []string{"VideoFrameRate", "FrameRate"} {
		if _, ok := exif[key]; ok {
			hasVideoExifKey = true
			break
		}
	}

	// If none of the above indicators are present, it's audio-only
	return !hasVideoTrack && !hasGeneralVideoCount && !hasVideoExifKey
}

func humanReadableSize(bytes int64) string {
	const unit = 1000
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB"}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), units[exp])
}

func getMimeType(filePath string, exif map[string]interface{}) string {
	if mime, ok := exif["MIMEType"]; ok {
		if s, ok := mime.(string); ok && s != "" && s != "application/unknown" {
			return s
		}
	}

	mimeType, err := magicmime.TypeByFile(filePath)
	if err != nil || mimeType == "" {
		return "unknown"
	}
	return mimeType
}

func computeHashes(filePath string) (map[string]string, error) {
	hashes := map[string]hash.Hash{
		"md5":      md5.New(),
		"sha1":     sha1.New(),
		"sha256":   sha256.New(),
		"sha512":   sha512.New(),
		"sha3-256": sha3.New256(),
		"sha3-512": sha3.New512(),
	}

	blake256, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}
	blake512, err := blake2b.New512(nil)
	if err != nil {
		return nil, err
	}
	hashes["blake2b-256"] = blake256
	hashes["blake2b-512"] = blake512

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	writers := make([]io.Writer, 0, len(hashes))
	for _, h := range hashes {
		writers = append(writers, h)
	}
	multi := io.MultiWriter(writers...)
	_, err = io.Copy(multi, file)
	if err != nil {
		return nil, err
	}

	results := make(map[string]string)
	for name, h := range hashes {
		results[name] = hex.EncodeToString(h.Sum(nil))
	}
	return results, nil
}

func main() {
	if err := magicmime.Open(magicmime.MAGIC_MIME_TYPE); err != nil {
		fmt.Printf("Failed to initialize libmagic: %v\n", err)
		os.Exit(1)
	}
	defer magicmime.Close()

	if len(os.Args) < 2 {
		fmt.Println("Usage: mediainfo-cli <file>")
		os.Exit(1)
	}
	filePath := os.Args[1]

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		fmt.Printf("Error getting file size: %v\n", err)
		os.Exit(1)
	}

	exif, err := getExifData(filePath)
	if err != nil {
		fmt.Printf("Error reading EXIF: %v\n", err)
		os.Exit(1)
	}

	media, err := getMediaInfo(filePath)
	if err != nil {
		fmt.Printf("Error reading MediaInfo: %v\n", err)
		os.Exit(1)
	}

	fileSize := fileInfo.Size()
	fileSizeHuman := humanReadableSize(fileSize)
	duration := extractDuration(exif, media)
	isEnc := isEncrypted(media)
	mimeType := getMimeType(filePath, exif)

	fileExt := "txt"
	if ext, ok := exif["FileTypeExtension"].(string); ok && ext != "" {
		fileExt = strings.ToLower(ext)
	}

	isAnim := isAnimation(mimeType, exif, media)
	videoAudioOnly := isVideoWithAudioOnly(mimeType, exif, media)
	hashes, err := computeHashes(filePath)
	if err != nil {
		fmt.Printf("Error computing file hashes: %v\n", err)
		os.Exit(1)
	}

	result := MediaMetadata{
		FileName:                filePath,
		MimeType:                mimeType,
		FileSize:                fileSize,
		FileExt:                 fileExt,
		FileSizeHuman:           fileSizeHuman,
		Duration:                duration,
		MediaIsAnimation:        isAnim,
		MediaIsEncrypted:        isEnc,
		MediaVideoWithAudioOnly: videoAudioOnly,
		Hashes:                  hashes,
		EXIF:                    exif,
		Media:                   media,
	}

	resultJson, err := json.Marshal(result)
	if err != nil {
		fmt.Printf("Failed to marshal result: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(resultJson))
}
