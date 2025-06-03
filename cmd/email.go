/*
Copyright © 2025 Matt Krueger <mkrueger@rstms.net>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.

 2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.

 3. Neither the name of the copyright holder nor the names of its contributors
    may be used to endorse or promote products derived from this software
    without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/
package cmd

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/emersion/go-message/mail"
)

func addPart(mailWriter *mail.Writer, buf *bytes.Buffer) error {
	part, err := mailWriter.CreateInline()
	defer part.Close()
	if err != nil {
		return err
	}
	var header mail.InlineHeader
	header.Set("Content-Type", "text/plain")
	writer, err := part.CreatePart(header)
	defer writer.Close()
	if err != nil {
		return err
	}
	_, err = io.WriteString(writer, buf.String())
	if err != nil {
		return err
	}
	return nil
}

func formatMessage(username, domain, filename string, buf *bytes.Buffer) error {

	from := []*mail.Address{{Name: "Sieve Daemon", Address: fmt.Sprintf("SIEVE-DAEMON@%s", domain)}}
	to := []*mail.Address{{Address: username + "@" + domain}}

	var mailHeader mail.Header
	mailHeader.SetDate(time.Now())
	mailHeader.SetAddressList("From", from)
	mailHeader.SetAddressList("To", to)
	_, basename := filepath.Split(filename)
	mailHeader.SetSubject(fmt.Sprintf("Sieve Trace: %s", basename))

	mailWriter, err := mail.CreateWriter(buf, mailHeader)
	if err != nil {
		return err
	}
	defer mailWriter.Close()

	/*
		var pbuf bytes.Buffer
		pbuf.WriteString(fmt.Sprintf("Sieve Trace file: %s\n", basename))
		err = c.addPart(mailWriter, &pbuf)
		if err != nil {
			return err
		}
	*/

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	err = addPart(mailWriter, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	return nil
}

func SendFile(username, domain, filename string) error {

	var buf bytes.Buffer
	err := formatMessage(username, domain, filename, &buf)
	if err != nil {
		return err
	}
	log.Printf("Sending %s to %s@%s\n", filename, username, domain)
	cmd := exec.Command("sendmail", "-t")
	cmd.Stdin = bytes.NewReader(buf.Bytes())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sendmail failed: %s", string(output))
	}
	return nil
}
