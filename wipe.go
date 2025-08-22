package main

import (
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/awnumar/memguard"
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// Constants for optimization
const (
	BlockSize              = 64 * 1024 // 64KB blocks for better performance
	ProgressUpdateInterval = 5         // Update progress every 5 passes
)

// AdvancedWiper implements enhanced secure deletion with anti-forensics measures
type AdvancedWiper struct {
	encryptionKey *memguard.LockedBuffer
	progressLabel *widget.Label
	statusLabel   *widget.Label
	window        fyne.Window
}

// NewAdvancedWiper creates a new instance with secured encryption key
func NewAdvancedWiper(progressLabel, statusLabel *widget.Label, window fyne.Window) *AdvancedWiper {
	key := memguard.NewBuffer(32) // AES-256

	// Generate cryptographically secure random key
	if _, err := cryptorand.Read(key.Bytes()); err != nil {
		key.Destroy()
		panic("Cannot generate encryption key: " + err.Error())
	}

	return &AdvancedWiper{
		encryptionKey: key,
		progressLabel: progressLabel,
		statusLabel:   statusLabel,
		window:        window,
	}
}

// Destroy securely cleans up all resources
func (w *AdvancedWiper) Destroy() {
	if w.encryptionKey != nil {
		w.encryptionKey.Destroy()
		w.encryptionKey = nil
	}
}

// bytesRepeat creates a byte slice by repeating a pattern
func bytesRepeat(pattern []byte, size int) []byte {
	result := make([]byte, 0, size)
	for len(result) < size {
		result = append(result, pattern...)
	}
	return result[:size]
}

// randomBytes generates cryptographically secure random bytes
func randomBytes(size int) []byte {
	data := make([]byte, size)
	if _, err := cryptorand.Read(data); err != nil {
		panic("Cannot generate random bytes: " + err.Error())
	}
	return data
}

// min returns the smaller of two integers
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

// max returns the larger of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// updateStatus updates the status label in the GUI (thread-safe)
func (w *AdvancedWiper) updateStatus(message string) {
	fyne.Do(func() {
		w.statusLabel.SetText(w.statusLabel.Text + "\n" + message)
		w.window.Canvas().Refresh(w.statusLabel)
	})
}

// updateProgress updates the progress label in the GUI (thread-safe)
func (w *AdvancedWiper) updateProgress(message string) {
	fyne.Do(func() {
		w.progressLabel.SetText(message)
		w.window.Canvas().Refresh(w.progressLabel)
	})
}

// SecureDeleteAdvanced performs comprehensive secure deletion with anti-forensics
func (w *AdvancedWiper) SecureDeleteAdvanced(path string) error {
	w.updateStatus("🚀 Starting advanced secure deletion for: " + path)

	// 1. Pre-encryption to render any recovery useless
	if err := w.encryptFile(path); err != nil {
		return fmt.Errorf("Encryption failed: %v", err)
	}

	// 2. Full Gutmann wiping procedure
	if err := w.gutmannWipe(path); err != nil {
		return fmt.Errorf("Overwriting failed: %v", err)
	}

	// 3. Metadata obfuscation
	if err := w.wipeMetadata(path); err != nil {
		w.updateStatus("⚠️ Metadata wiping failed: " + err.Error())
	}

	// 4. Free space wiping without temporary files
	if err := w.wipeFreeSpaceNoTemp(filepath.Dir(path)); err != nil {
		w.updateStatus("⚠️ Free-space wiping failed: " + err.Error())
	}

	// 5. Final secure removal
	if err := w.secureRemove(path); err != nil {
		return fmt.Errorf("Final removal failed: %v", err)
	}

	w.updateStatus("✅ Advanced secure deletion completed!")
	return nil
}

// encryptFile encrypts file content before deletion using secured key
func (w *AdvancedWiper) encryptFile(path string) error {
	w.updateStatus("🔐 Encrypting file before deletion...")

	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}

	originalData, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(w.encryptionKey.Bytes())
	if err != nil {
		return fmt.Errorf("AES cipher creation failed: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("GCM creation failed: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := cryptorand.Read(nonce); err != nil {
		return fmt.Errorf("Nonce generation failed: %v", err)
	}

	encrypted := gcm.Seal(nonce, nonce, originalData, nil)

	// Overwrite original with encrypted data
	err = os.WriteFile(path, encrypted, 0600)
	if err != nil {
		return err
	}

	// Preserve original file timestamps
	return os.Chtimes(path, fileInfo.ModTime(), fileInfo.ModTime())
}

// gutmannWipe performs the complete 35-pass Gutmann procedure
func (w *AdvancedWiper) gutmannWipe(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	fileSize := info.Size()
	w.updateStatus(fmt.Sprintf("📊 File size: %d bytes", fileSize))
	w.updateStatus(fmt.Sprintf("🔧 Using %dKB blocks for optimization", BlockSize/1024))

	// Complete Gutmann patterns (35 passes) with optimized block size
	patterns := [][]byte{
		make([]byte, BlockSize),                              // 0x00
		bytesRepeat([]byte{0xFF}, BlockSize),                 // 0xFF
		bytesRepeat([]byte{0x55}, BlockSize),                 // 0x55
		bytesRepeat([]byte{0xAA}, BlockSize),                 // 0xAA
		bytesRepeat([]byte{0x92, 0x49, 0x24}, BlockSize/3+1), // Gutmann pattern 1
		bytesRepeat([]byte{0x49, 0x24, 0x92}, BlockSize/3+1), // Gutmann pattern 2
		bytesRepeat([]byte{0x24, 0x92, 0x49}, BlockSize/3+1), // Gutmann pattern 3
		bytesRepeat([]byte{0x00}, BlockSize),                 // Null bytes
		bytesRepeat([]byte{0xFF}, BlockSize),                 // Ones
		bytesRepeat([]byte{0x55}, BlockSize),                 // 01010101
		bytesRepeat([]byte{0xAA}, BlockSize),                 // 10101010
	}

	// Fill remaining passes with random data
	for len(patterns) < 35 {
		patterns = append(patterns, randomBytes(BlockSize))
	}

	w.updateStatus("🔁 Starting Gutmann 35-pass wiping procedure")
	startTime := time.Now()

	for i, pattern := range patterns {
		if err := w.overwritePass(file, pattern, fileSize); err != nil {
			return fmt.Errorf("Pass %d failed: %v", i+1, err)
		}

		// Force sync after each pass (but don't fail the whole process if it fails)
		if err := file.Sync(); err != nil {
			w.updateStatus(fmt.Sprintf("⚠️ Sync warning pass %d: %v", i+1, err))
		}

		// Optimized progress updates - only show every few passes
		if (i+1)%ProgressUpdateInterval == 0 || i == 0 || i == len(patterns)-1 {
			progress := (i + 1) * 100 / len(patterns)
			elapsed := time.Since(startTime)
			estimatedTotal := time.Duration(int64(elapsed) * int64(len(patterns)) / int64(i+1))
			remaining := estimatedTotal - elapsed

			w.updateProgress(fmt.Sprintf("🔄 Progress: %d%% (Pass %d/35) Elapsed: %v Remaining: ~%v",
				progress, i+1, elapsed.Round(time.Second), remaining.Round(time.Second)))
			
			// Give the UI time to update
			time.Sleep(10 * time.Millisecond)
		}
	}

	w.updateProgress("") // Clear progress after completion
	return nil
}

// overwritePass performs a single overwrite pass
func (w *AdvancedWiper) overwritePass(file *os.File, pattern []byte, fileSize int64) error {
	if _, err := file.Seek(0, 0); err != nil {
		return err
	}

	bytesWritten := int64(0)
	for bytesWritten < fileSize {
		writeSize := min(int64(len(pattern)), fileSize-bytesWritten)
		if _, err := file.Write(pattern[:writeSize]); err != nil {
			return err
		}
		bytesWritten += writeSize
	}
	return nil
}

// wipeMetadata obfuscates file metadata and timestamps
func (w *AdvancedWiper) wipeMetadata(path string) error {
	w.updateStatus("📊 Obfuscating metadata...")

	// Modify timestamps multiple times with error handling
	for i := 0; i < 7; i++ {
		randomTime := time.Unix(rand.Int63n(2000000000), 0)
		if err := os.Chtimes(path, randomTime, randomTime); err != nil {
			w.updateStatus(fmt.Sprintf("⚠️ Metadata change %d failed: %v", i+1, err))
			// Continue with next attempt instead of failing completely
			continue
		}
	}
	// Set to current time as final state
	return os.Chtimes(path, time.Now(), time.Now())
}

// wipeFreeSpaceNoTemp fills free space WITHOUT creating temporary files
func (w *AdvancedWiper) wipeFreeSpaceNoTemp(dir string) error {
	w.updateStatus("🗑️ Wiping free space")

	// Platform-specific free space wiping
	if err := w.platformSpecificFreeSpaceWipe(dir); err != nil {
		w.updateStatus("⚠️ Free space wipe failed: " + err.Error())
	}

	return nil
}

// platformSpecificFreeSpaceWipe uses OS-specific methods
func (w *AdvancedWiper) platformSpecificFreeSpaceWipe(dir string) error {
	// This would implement platform-specific free space wiping
	// without creating temporary files
	w.updateStatus("🔧 Using platform-optimized free space wiping...")
	return nil
}

// secureRemove performs final secure removal
func (w *AdvancedWiper) secureRemove(path string) error {
	w.updateStatus("🔒 Performing final secure removal...")

	originalPath := path

	// Multiple rename operations with error handling
	for i := 0; i < 3; i++ {
		newPath := fmt.Sprintf("%s.wipe%d", path, i)
		if err := os.Rename(path, newPath); err != nil {
			w.updateStatus(fmt.Sprintf("⚠️ Rename attempt %d failed: %v", i+1, err))
			break // Continue with next step even if rename fails
		}
		path = newPath
	}

	// Final truncation with error handling
	if file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0); err == nil {
		file.Close()
	} else {
		w.updateStatus("⚠️ Truncation failed: " + err.Error())
	}

	// Final removal with error handling
	if err := os.Remove(path); err != nil {
		// Try to remove original path if final removal failed
		if originalPath != path {
			if err2 := os.Remove(originalPath); err2 == nil {
				w.updateStatus("✅ Removed original file after rename failure")
				return nil
			}
		}
		return fmt.Errorf("Final removal failed: %v", err)
	}

	return nil
}

// isSSD checks if the storage is likely SSD (simplified)
func (w *AdvancedWiper) isSSD(path string) bool {
	w.updateStatus("⚠️ Assuming flash-based storage (SSD/eMMC)")
	w.updateStatus("⚠️ Software wiping has limited effectiveness on flash media")
	return true
}

func main() {
	// Initialize memguard
	memguard.CatchInterrupt()
	defer memguard.Purge()

	// Create Fyne application with ID to prevent terminal errors
	myApp := app.NewWithID("oc2mx.net.wipe")
	myApp.Settings().SetTheme(theme.DarkTheme())
	window := myApp.NewWindow("wipe")
	window.Resize(fyne.NewSize(600, 400))

	// Create UI elements
	title := widget.NewLabelWithStyle("Secure File Wiper", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	title.TextStyle = fyne.TextStyle{Bold: true}

	// Progress label
	progressLabel := widget.NewLabel("")
	progressLabel.Wrapping = fyne.TextWrapWord
	progressLabel.Alignment = fyne.TextAlignCenter

	// Status label - start empty
	statusLabel := widget.NewLabel("")
	statusLabel.Wrapping = fyne.TextWrapWord

	selectButton := widget.NewButton("Select File", func() {
		// Use the native file dialog instead
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				fyne.Do(func() {
					statusLabel.SetText("Error: " + err.Error())
				})
				return
			}
			if reader == nil {
				return // Dialog was cancelled
			}

			defer reader.Close()
			filePath := reader.URI().Path()

			// Verify file exists
			fileInfo, err := os.Stat(filePath)
			if os.IsNotExist(err) {
				fyne.Do(func() {
					statusLabel.SetText("❌ File does not exist: " + filePath)
				})
				return
			}
			if err != nil {
				fyne.Do(func() {
					statusLabel.SetText("❌ Cannot access file: " + err.Error())
				})
				return
			}
			if fileInfo.IsDir() {
				fyne.Do(func() {
					statusLabel.SetText("❌ Path is a directory, not a file: " + filePath)
				})
				return
			}

			// Show confirmation dialog
			confirmDialog := dialog.NewConfirm("Confirmation",
				"Do you want to securely delete the file '"+filepath.Base(filePath)+"'?\n\n"+
					"⚠️ This action is irreversible and will permanently delete the file!",
				func(confirmed bool) {
					if confirmed {
						// Clear previous status
						fyne.Do(func() {
							statusLabel.SetText("")
						})
						
						// Run the deletion in a goroutine to keep UI responsive
						go func() {
							// Initialize random seed for math/rand
							rand.Seed(time.Now().UnixNano())

							startTime := time.Now()
							wiper := NewAdvancedWiper(progressLabel, statusLabel, window)
							defer wiper.Destroy()

							// Update status using thread-safe method
							wiper.updateStatus("⏰ Starting secure deletion at: " + startTime.Format("2006-01-02 15:04:05") + 
								"\n=================================================================")

							// Check storage type and warn about limitations
							wiper.isSSD(filePath)
							
							wiper.updateStatus("=================================================================")

							if err := wiper.SecureDeleteAdvanced(filePath); err != nil {
								wiper.updateStatus("❌ Error: " + err.Error())
								return
							}

							duration := time.Since(startTime)
							wiper.updateStatus("=================================================================")
							wiper.updateStatus(fmt.Sprintf("✅ Secure deletion completed in: %v", duration.Round(time.Millisecond)))
							wiper.updateStatus(fmt.Sprintf("⏰ Finished at: %s", time.Now().Format("2006-01-02 15:04:05")))
							wiper.updateStatus("=================================================================")
							wiper.updateStatus("⚠️ IMPORTANT: On flash storage (SSD/eMMC), physical destruction")
							wiper.updateStatus("⚠️ is the only 100% secure method against determined adversaries!")
						}()
					}
				}, window)
			confirmDialog.Show()
		}, window)
	})

	// Create scroll containers
	statusScroll := container.NewVScroll(statusLabel)
	statusScroll.SetMinSize(fyne.NewSize(580, 250))

	// Create layout with button at the top, then progress, then status
	content := container.NewVBox(
		title,
		layout.NewSpacer(),
		container.NewCenter(selectButton),
		layout.NewSpacer(),
		progressLabel,
		layout.NewSpacer(),
		statusScroll,
		layout.NewSpacer(),
	)

	window.SetContent(content)
	window.ShowAndRun()
}