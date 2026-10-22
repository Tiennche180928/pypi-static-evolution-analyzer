# PyPI Malware Static & Version Evolution Analyzer

[![Python](https://img.shields.io/badge/Python-Tested%20on%203.12-blue.svg)](https://www.python.org/)
![Dependencies](https://img.shields.io/badge/Dependencies-Pure%20Stdlib-brightgreen.svg)
![Interface](https://img.shields.io/badge/Interface-CLI-orange.svg)
![Analysis](https://img.shields.io/badge/Analysis-No%20Sample%20Execution-red.svg)

> Công cụ dòng lệnh hỗ trợ phân tích tĩnh và theo dõi thay đổi giữa các phiên bản package PyPI trong nghiên cứu bảo mật chuỗi cung ứng phần mềm. Công cụ đọc mã nguồn mà không cài đặt hoặc thực thi package mẫu; kết quả so sánh được in ra terminal và tự lưu vào từng phiên bản dưới tên `version_changes.md`.

## Chức năng chính

- **Quét tĩnh mã nguồn:** sử dụng Python AST và các quy tắc đối sánh để tìm dấu hiệu thực thi lệnh, hook cài đặt, làm rối mã, kết nối mạng và truy cập dữ liệu nhạy cảm trong các tệp `.py`, `.pth`.
- **So sánh chuỗi phiên bản:** tự tìm các version local của package được chọn, sắp xếp theo tên version và đối chiếu từng cặp liền nhau trong dữ liệu tìm được.
- **Báo cáo theo từng version:** mỗi bản có báo cáo riêng, ghi rõ version đối chiếu, danh sách thay đổi và diff ngay bên dưới.
- **Đối chiếu mọi loại tệp trong nguồn được chọn:** thống kê tệp thêm, sửa, xóa; tạo diff cho văn bản UTF-8 và hiển thị SHA-256 trước/sau cho tệp nhị phân hoặc không giải mã được UTF-8.
- **Đa định dạng, không cần thư viện ngoài:** hỗ trợ `.tar.gz`, `.tgz`, `.whl`, `.zip`, script `.py` và thư mục mã nguồn; sử dụng thư viện chuẩn Python.

## Những thay đổi trong bản cập nhật

| Hạng mục | Nội dung đã sửa hoặc bổ sung |
|---|---|
| Nhận diện dataset | Đọc được cấu trúc `<package>/<version>/src.zip`, thay vì gom cả package thành một mẫu `single` khi không nhận ra các version bên trong. |
| Tên báo cáo | Thống nhất dùng `version_changes.md` trong mỗi thư mục version. |
| Lệnh mặc định | `diff <package>` vừa in đầy đủ báo cáo ra terminal, vừa tự lưu báo cáo; không cần thêm cờ xuất tệp. |
| Nội dung báo cáo | Chỉ giữ **mô tả thay đổi** và **diff đối chiếu**; phần quét dấu hiệu bảo mật dùng lệnh `scan` riêng. |
| Gắn diff đúng version | Thay đổi từ bản A sang bản B được lưu trong thư mục bản B. Bản đầu có trong dữ liệu được ghi rõ là chưa có bản trước để so sánh. |
| Phạm vi diff | Bao gồm tệp thêm, sửa, xóa; ghi nhận cả tệp rỗng, thay đổi newline, tệp nhị phân và văn bản không phải UTF-8. |
| Độ đầy đủ | In tất cả các hunk thay đổi với ngữ cảnh, không cắt diff sau 40 dòng. |
| Chạy lại | Cập nhật báo cáo cố định và bỏ qua `version_changes.md` khi so sánh, tránh đưa báo cáo vào diff của chính nó. |
| Chọn nguồn và version | Loại trùng đường dẫn, tách version của wheel khỏi tag, thông báo nguồn được chọn khi có nhiều biến thể; xử lý `--v1` hoặc `--v2` dùng riêng. |
| Một version | Vẫn tạo báo cáo, ghi rõ chưa đủ bản để có diff giữa các version. |
| Lệnh `scan` | Khi truyền tên package, mở nguồn của bản local mới nhất tìm được; hiển thị số tệp Python/.pth kiểm tra và báo `INCOMPLETE` nếu bằng 0. |
| Xuất bổ sung | `--report` lưu thêm báo cáo tổng hợp; `--out-dir` lưu thêm bản sao theo package/version. |

## Chuẩn bị và chạy

Tải bản `pypi_analyzer.py` đã cập nhật, rồi đặt trong thư mục dataset hoặc gọi bằng đường dẫn tới script. Kiểm tra môi trường:

```bash
python --version
python pypi_analyzer.py --help
```

Trên Kali/Linux, dùng `python3` nếu máy không có lệnh `python`. Không cần chạy `pip install` cho các chức năng phân tích của công cụ.

Nếu tải qua Gist, hãy cập nhật nội dung script trên Gist bằng bản mới trước khi dùng các lệnh sau. Lệnh `curl` tải nội dung hiện đang được lưu tại địa chỉ đó.

**Windows — PowerShell:**

```powershell
curl.exe -L -o pypi_analyzer.py "https://gist.githubusercontent.com/Tiennche180928/11ef7e48a45e316db6598316bfca670d/raw/pypi_analyzer.py"
```

**macOS / Linux — Terminal:**

```bash
curl -L -o pypi_analyzer.py "https://gist.githubusercontent.com/Tiennche180928/11ef7e48a45e316db6598316bfca670d/raw/pypi_analyzer.py"
```

## Hướng dẫn sử dụng

### 1. Xem tổng quan kho mẫu

```bash
python pypi_analyzer.py list

# Chỉ định thư mục cần thống kê
python pypi_analyzer.py list /home/kali/datasets/Dataset-Tien
```

Hiển thị các mẫu nhận diện được, số package, số version, phân bố định dạng và danh sách package có nhiều version.

### 2. Phân tích chuỗi thay đổi và tự lưu báo cáo

Đứng tại thư mục dataset chứa các thư mục package:

```bash
cd /home/kali/datasets/Dataset-Tien

python pypi_analyzer.py diff ctx
python pypi_analyzer.py diff aws-login0tool
python pypi_analyzer.py diff fleshh
```

Mỗi lệnh xử lý **một package** được chọn. Các version local tìm được sẽ được đối chiếu từng cặp liền nhau, đồng thời in và lưu báo cáo.

Ví dụ dataset có ba bản `ctx`:

| Báo cáo tự tạo | Cặp phiên bản được mô tả |
|---|---|
| `ctx/0.1.2/version_changes.md` | Bản đầu có trong dữ liệu; chưa có bản trước để tạo diff |
| `ctx/0.2.2/version_changes.md` | `0.1.2 → 0.2.2` |
| `ctx/0.2.6/version_changes.md` | `0.2.2 → 0.2.6` |

### 3. Chọn riêng một cặp phiên bản

```bash
# Chọn cả bản đối chiếu và bản đích
python pypi_analyzer.py diff ctx --v1 0.1.2 --v2 0.2.6

# Chọn bản đối chiếu; bản đích mặc định là bản cuối tìm được
python pypi_analyzer.py diff ctx --v1 0.2.2

# Chọn bản đích; bản đối chiếu mặc định là bản đầu tìm được
python pypi_analyzer.py diff ctx --v2 0.2.2

# So sánh bản đầu và cuối
python pypi_analyzer.py diff aws-login0tool --first-last

# Truyền trực tiếp hai nguồn
python pypi_analyzer.py diff ctx/0.1.2/src.zip ctx/0.2.6/src.zip
```

Khi chọn một cặp, công cụ chỉ cập nhật báo cáo của **version đích**. Tên version truyền vào phải khớp với dữ liệu local.

### 4. Quét tĩnh một mẫu

```bash
# Quét nguồn của bản local mới nhất tìm được
python pypi_analyzer.py scan ctx

# Quét một archive cụ thể
python pypi_analyzer.py scan ctx/0.2.6/src.zip

# Lưu báo cáo quét riêng
python pypi_analyzer.py scan ctx --report reports/ctx_scan.md
```

Kết quả gồm các quy tắc khớp, mức cảnh báo, tệp, dòng và đoạn mã liên quan. Đây là những dấu hiệu cần xem xét; không có quy tắc khớp không chứng minh package là lành tính.

### 5. Xuất thêm bản sao hoặc JSON

```bash
# Lưu thêm báo cáo tổng hợp của chuỗi
python pypi_analyzer.py diff ctx --report reports/ctx_changes.md

# Lưu thêm các bản sao theo package/version
python pypi_analyzer.py diff ctx --out-dir reports/copies

# Xuất JSON ra stdout; vẫn tự lưu Markdown trong từng version
python pypi_analyzer.py diff ctx --json
```

`--out-dir reports/copies` tạo bản sao tại `reports/copies/<package>/<version>/version_changes.md`. Các tùy chọn này bổ sung bản xuất, trong khi báo cáo tại từng version vẫn được tạo như mặc định.

`--report` áp dụng cho `scan` và `diff`. `--all-diffs` được giữ để tương thích với lệnh cũ; hiện mọi diff đều được hiển thị. Nên lưu bản tổng hợp/bản sao ngoài thư mục mã nguồn được so sánh để tránh đưa chúng vào diff ở lần chạy sau.

### 6. So sánh với nguồn tham chiếu từ PyPI

```bash
python pypi_analyzer.py diff ctx/0.2.6/src.zip \
  --pypi-clean ctx --pypi-version 0.1.2
```

Công cụ tải phiên bản chỉ định từ PyPI làm nguồn đối chiếu và lưu báo cáo vào version local. Tên cờ `--pypi-clean` được giữ từ bản cũ; nguồn tải về chưa được công cụ xác minh là lành tính. Chức năng này cần mạng và chưa được kiểm thử với PyPI thật trong bản cập nhật này.

## Nội dung `version_changes.md`

Mỗi báo cáo ghi tên package, version hiện tại, version đối chiếu và đường dẫn nguồn; bên dưới có đúng hai phần:

1. **Mô tả thay đổi:** thống kê số tệp thêm/sửa/xóa và bảng mô tả từng tệp. Với Python hợp lệ, bổ sung tên hàm, lớp, import hoặc biến ở cấp module đã thay đổi khi xác định được.
2. **Diff đối chiếu:** unified diff cho từng tệp văn bản; với tệp nhị phân hoặc không phải UTF-8, ghi rõ không có diff văn bản và hiển thị SHA-256 trước/sau.

Diff nằm ngay trong Markdown. Không tạo HTML, thư mục `diffs/` hoặc tệp `.diff` riêng. Với bản đầu trong dữ liệu, báo cáo không tạo diff giả với một bản trước không tồn tại.

## Nguồn được đọc và vị trí lưu

| Kiểu đầu vào | Vị trí báo cáo mặc định |
|---|---|
| `ctx/0.2.6/src.zip` | `ctx/0.2.6/version_changes.md` |
| Archive bên trong thư mục version | Trong chính thư mục version đó |
| Thư mục mã nguồn của một version | Trong thư mục mã nguồn đó |
| Archive đặt phẳng như `ctx-0.2.6.tar.gz` | Tạo `ctx/0.2.6/version_changes.md` cạnh khu vực lưu archive |

Với `package/version/src.zip`, công cụ đọc các tệp bên trong archive được chọn. `metadata.json`, `README.md` hoặc `README.rst` nằm bên ngoài archive không được đưa vào diff trong chế độ này và được giữ nguyên.

Nếu có nhiều nguồn cho cùng version, công cụ chọn một nguồn đại diện theo ưu tiên: `.tar.gz`/`.tgz`, `.zip` có tên package-version, wheel, `src.zip`, rồi thư mục giải nén. Đường dẫn được chọn xuất hiện trong thông báo; chưa so sánh mọi biến thể của một version.

## Các nhóm dấu hiệu trong chế độ `scan`

| Nhóm quy tắc | Mức cảnh báo trong công cụ | Ví dụ dấu hiệu |
|---|---|---|
| `INSTALL_HOOKS` | CRITICAL | `cmdclass`, kế thừa lệnh cài đặt, `atexit.register`, dòng `import` trong `.pth` |
| `COMMAND_EXECUTION` | CRITICAL | `os.system`, `os.popen`, `subprocess`, `pty.spawn`, `os.dup2` |
| `DYNAMIC_EVAL` | CRITICAL | `exec`, `eval`, `compile` ở chế độ thực thi, `__import__` |
| `IMMEDIATE_EXECUTION` | CRITICAL | Một số cấu trúc ở cấp module trong `setup.py` có tham chiếu tới thao tác hệ thống hoặc mạng |
| `OBFUSCATION` | HIGH | Base64, đảo chuỗi, giải nén zlib, `codecs.decode`, chuỗi byte hex |
| `NETWORK_EXFILTRATION` | HIGH | Socket, lời gọi HTTP, địa chỉ IP hoặc URL được ghi trực tiếp |
| `RECONNAISSANCE_STEALER` | HIGH | Biến môi trường, thông tin người dùng/máy, đường dẫn thông tin nhạy cảm |

Các mức trên là nhãn của bộ quy tắc. Một thao tác hệ thống hoặc kết nối mạng cũng có thể phục vụ chức năng hợp lệ; kết quả cần được đọc cùng mã nguồn và ngữ cảnh nghiên cứu.

## Phạm vi và giới hạn

- **Không chạy package mẫu:** công cụ đọc tệp, phân tích AST và đối chiếu nội dung; có kiểm tra đường dẫn khi giải nén để hạn chế ghi ra ngoài thư mục tạm. Đây không phải cam kết “an toàn tuyệt đối”.
- **Lịch sử snapshot phát hành:** diff mô tả thay đổi giữa các nguồn tìm được; không khôi phục commit SHA, tác giả hoặc thời điểm commit Git gốc.
- **Thứ tự theo tên version:** dùng sắp xếp tự nhiên, chưa triển khai đầy đủ PEP 440 hoặc dùng upload time để dựng trình tự thời gian. Nếu thiếu bản trung gian, báo cáo ghi rõ hai bản thực tế được đối chiếu.
- **Không tự xác định Patient Zero:** công cụ hỗ trợ tìm vị trí thay đổi trong chuỗi đã có, chưa tự kết luận chính xác phiên bản đầu tiên bị cấy mã độc.
- **Chưa tích hợp cập nhật metadata và upload:** bổ sung `upload_time` hoặc tự đẩy lên Hugging Face với tên commit như `Update Upload Time litellm 1.0.1` là quy trình bổ sung, chưa phải chức năng của script hiện tại.

## Yêu cầu hệ thống và kiểm thử

- **Python:** bản cập nhật đã được kiểm thử trên Python 3.12. Các phiên bản khác cần kiểm tra tương thích; không giữ cam kết Python 3.8+ của tài liệu cũ.
- **Môi trường:** công cụ CLI dùng thư viện chuẩn Python, có thể triển khai trên Windows, macOS hoặc Linux với môi trường Python tương thích; chưa kiểm thử đầy đủ trên từng hệ điều hành.
- **Thư viện ngoài:** không cần cho các chức năng phân tích.
- **Mạng:** phân tích dữ liệu local không cần mạng; tải nguồn tham chiếu từ PyPI cần kết nối mạng.

Bộ cập nhật có dữ liệu demo tổng hợp và **21 ca kiểm thử đã chạy thành công**, bao gồm nhận diện version, tự lưu báo cáo, gắn đúng version đích, diff thêm/sửa/xóa, binary, newline, tệp rỗng, JSON và chạy lại mà không thay đổi archive đầu vào.

Chạy kiểm thử tại thư mục chứa script và `test_dataset_layout.py`:

```bash
python -m unittest discover -s . -p test_dataset_layout.py -v
```
