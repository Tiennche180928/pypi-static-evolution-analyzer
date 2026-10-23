## Điền đường dẫn, tên package và version của bạn

```bash
ANALYZER="/duong/dan/toi/pypi_analyzer.py"
DATASET_DIR="/duong/dan/toi/thu-muc-chua-package"
PACKAGE="ten-package"
VERSION_1="1.0.0"
VERSION_2="1.1.0"
OUTPUT_DIR="/duong/dan/ngoai-dataset/ket-qua"
```

## Vào thư mục chứa các package

```bash
cd "$DATASET_DIR"
```

## Xem trợ giúp

```bash
python3 "$ANALYZER" --help
python3 "$ANALYZER" diff --help
python3 "$ANALYZER" scan --help
```

## Liệt kê package

```bash
python3 "$ANALYZER" list "$DATASET_DIR"
```

## Chạy một package nhiều version

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE"
```

## Chạy một package chỉ có một version — tạo báo cáo bản đầu

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE"
```

## Chạy tất cả package trong thư mục đã chọn — tiếp tục khi một package lỗi

```bash
for package in "$DATASET_DIR"/*/; do
    [ -d "$package" ] || continue
    find "$package" -mindepth 1 -maxdepth 1 -type d \
        \( -name '[0-9]*' -o -name '[vV][0-9]*' \) \
        -print -quit | grep -q . || continue
    printf '\n===== %s =====\n' "$(basename "$package")"
    python3 "$ANALYZER" diff "$package" || \
        printf 'Lỗi: %s\n' "$package" >&2
done
```

## Chạy một danh sách package — thay các tên ví dụ

```bash
for package in ten-package-1 ten-package-2 ten-package-3; do
    python3 "$ANALYZER" diff "$DATASET_DIR/$package" || \
        printf 'Lỗi: %s\n' "$package" >&2
done
```

## So sánh hai version cụ thể

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE" --v1 "$VERSION_1" --v2 "$VERSION_2"
```

## So sánh version được chọn với bản cuối tìm được

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE" --v1 "$VERSION_1"
```

## So sánh bản đầu tìm được với version đích

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE" --v2 "$VERSION_2"
```

## So sánh bản đầu và bản cuối

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE" --first-last
```

## So sánh trực tiếp hai src.zip

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE/$VERSION_1/src.zip" "$DATASET_DIR/$PACKAGE/$VERSION_2/src.zip"
```

## So sánh trực tiếp hai archive phát hành

```bash
python3 "$ANALYZER" diff "/duong/dan/toi/package-1.0.0.tar.gz" "/duong/dan/toi/package-1.1.0.tar.gz"
```

## Quét tĩnh bản local mới nhất của một package

```bash
python3 "$ANALYZER" scan "$DATASET_DIR/$PACKAGE"
```

## Quét tĩnh một archive cụ thể

```bash
python3 "$ANALYZER" scan "$DATASET_DIR/$PACKAGE/$VERSION_2/src.zip"
```

## Quét tĩnh một tệp Python

```bash
python3 "$ANALYZER" scan "/duong/dan/toi/mau.py"
```

## Quét tĩnh tất cả package trong thư mục đã chọn

```bash
for package in "$DATASET_DIR"/*/; do
    [ -d "$package" ] || continue
    find "$package" -mindepth 1 -maxdepth 1 -type d \
        \( -name '[0-9]*' -o -name '[vV][0-9]*' \) \
        -print -quit | grep -q . || continue
    printf '\n===== %s =====\n' "$(basename "$package")"
    python3 "$ANALYZER" scan "$package" || \
        printf 'Lỗi: %s\n' "$package" >&2
done
```

## Lưu thêm báo cáo tổng hợp bên ngoài dataset

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE" --report "$OUTPUT_DIR/${PACKAGE}_changes.md"
```

## Lưu thêm bản sao báo cáo từng version bên ngoài dataset

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE" --out-dir "$OUTPUT_DIR/copies"
```

## Lưu báo cáo quét tĩnh bên ngoài dataset

```bash
python3 "$ANALYZER" scan "$DATASET_DIR/$PACKAGE" --report "$OUTPUT_DIR/${PACKAGE}_scan.md"
```

## In kết quả diff dạng JSON

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE" --json
```

## Lưu JSON bên ngoài dataset

```bash
mkdir -p "$OUTPUT_DIR"
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE" --json > "$OUTPUT_DIR/${PACKAGE}_changes.json"
```

## Tắt màu khi quét tĩnh

```bash
python3 "$ANALYZER" scan "$DATASET_DIR/$PACKAGE" --no-color
```

## So sánh với nguồn tham chiếu PyPI — cần mạng

```bash
python3 "$ANALYZER" diff "$DATASET_DIR/$PACKAGE/$VERSION_2/src.zip" --pypi-clean "$PACKAGE" --pypi-version "$VERSION_1"
```
