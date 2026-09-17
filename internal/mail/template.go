package mail

import (
	"fmt"
	"html"
	"strings"
)

// otpEmailHTML renders a small branded HTML email around a one-time code —
// inline styles throughout since email clients don't reliably load <style>
// blocks or external CSS. Matches the app's indigo brand color (#4F46E5).
func otpEmailHTML(heading, message, otp string) string {
	heading = html.EscapeString(heading)
	message = strings.ReplaceAll(html.EscapeString(message), "\r\n", "<br>")
	message = strings.ReplaceAll(message, "\n", "<br>")
	otp = html.EscapeString(otp)

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background-color:#F5F6FA;font-family:'Segoe UI',Arial,sans-serif;">
  <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background-color:#F5F6FA;padding:40px 0;">
    <tr>
      <td align="center">
        <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="background-color:#FFFFFF;border-radius:14px;overflow:hidden;box-shadow:0 4px 16px rgba(17,24,39,0.08);">
          <tr>
            <td style="background-color:#4F46E5;background-image:linear-gradient(135deg,#4F46E5,#6D5EF0);padding:28px 36px;">
              <span style="color:#FFFFFF;font-size:20px;font-weight:700;letter-spacing:0.2px;">ARMSS Gateway</span>
            </td>
          </tr>
          <tr>
            <td style="padding:36px;">
              <h2 style="margin:0 0 12px;color:#111827;font-size:18px;font-weight:700;">%s</h2>
              <p style="margin:0 0 24px;color:#6B7280;font-size:14px;line-height:1.6;">%s</p>
              <table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background-color:#EEF2FF;border-radius:10px;">
                <tr>
                  <td align="center" style="padding:22px;">
                    <span style="font-size:34px;font-weight:700;letter-spacing:10px;color:#4F46E5;font-family:'IBM Plex Mono',Consolas,monospace;">%s</span>
                  </td>
                </tr>
              </table>
              <p style="margin:24px 0 0;color:#9CA3AF;font-size:12px;line-height:1.5;">This code expires in 15 minutes. If you didn't request this, you can safely ignore this email.</p>
            </td>
          </tr>
          <tr>
            <td style="padding:16px 36px;background-color:#F1F3F9;text-align:center;">
              <span style="color:#9CA3AF;font-size:11px;">ARMSS Group of Companies</span>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`, heading, message, otp)
}
