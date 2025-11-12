# PR Template: Fix False Positive trong TCP Stream Detection

## Tóm tắt ngắn gọn
Mô tả ngắn gọn vấn đề được fix và giải pháp (1-2 câu)

## Vấn đề (Problem)

### Mô tả chi tiết
Mô tả chi tiết vấn đề gây ra false positive:
- Lỗi cụ thể là gì?
- Tại sao lỗi này gây false positive?
- Ảnh hưởng đến hệ thống như thế nào?

### Root Cause Analysis
Phân tích nguyên nhân gốc rễ:
- Module/function nào có lỗi?
- Code ở dòng nào?
- Logic sai ở chỗ nào?

### Reproduction Steps
Các bước để reproduce lỗi:
1. Setup environment...
2. Chạy IDS với config...
3. Send traffic pattern...
4. Observe false positive...

### Evidence
Bằng chứng về lỗi:
- Log snippets
- Screenshots (nếu có)
- Metrics/stats

## Giải pháp (Solution)

### Cách tiếp cận
Mô tả cách tiếp cận để fix:
- Strategy chọn là gì? (e.g., refactor reassembly logic, add state machine, etc.)
- Tại sao chọn cách này?
- Có xem xét alternatives không?

### Code Changes
List các thay đổi code chính:

#### 1. File: `app/capture_packet/ids_byte_deep.py`
**Changes:**
- [ ] Refactor `TCPReassembler.feed()` method
  - Thêm xử lý out-of-order segments (Line XXX)
  - Thêm duplicate detection cho retransmissions (Line YYY)
  - Thêm TCP flags handling (SYN, FIN, RST) (Line ZZZ)
- [ ] Update timeout values
  - TCP timeout: 120s → 30s (Line AAA)
  - IP timeout: 30s → 15s (Line BBB)
- [ ] Improve duplicate detection
  - Thay đổi hash logic (Line CCC)
  - Thêm timestamp tracking (Line DDD)

#### 2. File: `tests/test_tcp_reassembler.py` (NEW)
**Purpose:** Unit tests cho TCP reassembly logic
**Test cases:**
- [ ] test_in_order_segments()
- [ ] test_out_of_order_segments()
- [ ] test_retransmissions()
- [ ] test_overlapping_segments()
- [ ] test_syn_fin_rst_handling()
- [ ] test_connection_reuse()
- [ ] test_timeout_cleanup()

#### 3. Other files...
(List other changed files)

### Algorithm/Logic Changes
Mô tả thay đổi algorithm/logic (nếu phức tạp):
```python
# BEFORE:
def old_logic():
    # Mô tả logic cũ
    pass

# AFTER:
def new_logic():
    # Mô tả logic mới
    pass
```

## Testing

### Test Strategy
Mô tả chiến lược testing:
- Unit tests cho các functions changed
- Integration tests với PCAP files
- Performance tests với high traffic
- Regression tests cho existing functionality

### Test Cases

#### Unit Tests
| Test Name | Purpose | Expected Result | Status |
|-----------|---------|----------------|--------|
| test_out_of_order | Test out-of-order segments | Reassemble chính xác | ✅ PASS |
| test_retransmission | Test duplicate seq handling | Không duplicate alert | ✅ PASS |
| test_overlapping | Test overlapping segments | Reassemble without corruption | ✅ PASS |
| ... | ... | ... | ... |

#### Integration Tests (PCAP-based)
| PCAP File | Scenario | Expected Alerts | Actual Alerts | Status |
|-----------|----------|----------------|---------------|--------|
| test_out_of_order.pcap | Out-of-order segments | 1 | 1 | ✅ PASS |
| test_retrans.pcap | Retransmissions | 1 | 1 | ✅ PASS |
| ... | ... | ... | ... | ... |

#### Performance Tests
| Metric | Before | After | Change | Status |
|--------|--------|-------|--------|--------|
| False Positive Rate | 55% | 15% | -40% | ✅ IMPROVED |
| Memory Usage | 500MB | 350MB | -30% | ✅ IMPROVED |
| CPU Usage | 45% | 47% | +2% | ⚠️ ACCEPTABLE |
| Packet Drop Rate | 0.5% | 0.5% | 0% | ✅ OK |

### Test Results Summary
- Total tests: XX
- Passed: YY
- Failed: ZZ
- Skipped: AA

### Manual Testing
Mô tả manual testing đã thực hiện:
1. Test với live traffic trên interface eth0 trong 1 giờ
2. Kiểm tra alerts log - không thấy duplicate alerts
3. Monitor memory usage - stable, không leak
4. Check CPU usage - tăng nhẹ (acceptable)

## Impact Assessment

### Performance Impact
- **Memory**: Giảm 30% (từ 500MB → 350MB)
- **CPU**: Tăng 2% (từ 45% → 47%)
- **Throughput**: Không thay đổi
- **Latency**: Không thay đổi đáng kể

### False Positive Rate
- **Before**: 55% (55 false positives / 100 alerts)
- **After**: 15% (15 false positives / 100 alerts)
- **Improvement**: **-40 percentage points** ✅

### Breaking Changes
- [ ] Có breaking changes (mô tả dưới)
- [x] Không có breaking changes

**Nếu có breaking changes, mô tả:**
- API changes...
- Config format changes...
- Migration guide...

### Backward Compatibility
- [x] Fully backward compatible
- [ ] Requires migration (mô tả migration steps)

## Security Considerations

### Security Impact
- [ ] Giảm false negatives (improve detection)
- [x] Giảm false positives (reduce noise)
- [ ] Thêm attack vectors mới (BAD - cần fix)
- [ ] No security impact

### Vulnerabilities Addressed
List các vulnerabilities được fix (nếu có):
- CVE-XXXX-YYYY: ...
- Security issue #ZZZ: ...

### New Vulnerabilities Introduced
- [x] Không có vulnerabilities mới
- [ ] Có vulnerabilities mới (MUST FIX BEFORE MERGE)

## Documentation

### Code Documentation
- [x] Code comments added/updated
- [x] Docstrings added/updated
- [x] Inline comments for complex logic

### User Documentation
- [x] README updated (if needed)
- [x] CHANGELOG updated
- [x] API documentation updated (if needed)

### Developer Documentation
- [x] Architecture diagram updated (if needed)
- [x] Development guide updated
- [x] Testing guide added

## Deployment

### Deployment Checklist
- [ ] Backup current rules.json
- [ ] Stop IDS service
- [ ] Deploy new code
- [ ] Disable NIC offload (run `disable_nic_offload.sh`)
- [ ] Restart IDS service
- [ ] Monitor logs for 1 hour
- [ ] Check false positive rate
- [ ] Verify memory/CPU usage

### Rollback Plan
Nếu có issues sau deploy:
1. Stop IDS service
2. Restore backup code
3. Restart IDS service
4. Report issues to team

### Monitoring
Sau khi deploy, monitor các metrics:
- False positive rate (target: <20%)
- Memory usage (target: <400MB, no leaks)
- CPU usage (target: <50%)
- Packet drop rate (target: <1%)
- Alert count per minute (detect alert storms)

## Review Checklist

### Code Quality
- [ ] Code follows project style guide
- [ ] No hardcoded values (use constants)
- [ ] Error handling added
- [ ] Logging added for debugging
- [ ] No commented-out code (except for explanatory purposes)
- [ ] No debug print statements

### Testing
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] All tests pass locally
- [ ] Performance tests pass
- [ ] Manual testing completed

### Documentation
- [ ] Code comments adequate
- [ ] README updated (if needed)
- [ ] CHANGELOG updated
- [ ] PR description complete

### Security
- [ ] No secrets in code
- [ ] No SQL injection vulnerabilities
- [ ] No XSS vulnerabilities
- [ ] No hardcoded credentials
- [ ] Input validation added

### Performance
- [ ] No obvious performance regressions
- [ ] Memory leaks checked
- [ ] CPU usage acceptable
- [ ] Scalability considered

## Related Issues/PRs
- Closes #XXX
- Related to #YYY
- Depends on #ZZZ
- Blocks #AAA

## Screenshots/Logs
(Attach screenshots, log samples, or metrics graphs nếu có)

### Before Fix
```
[Sample log showing false positives]
```

### After Fix
```
[Sample log showing fix working]
```

## Reviewers
Tag reviewers:
- @security-team (required)
- @ids-maintainers (required)
- @performance-team (optional)

## Additional Notes
Bất kỳ notes thêm cho reviewers hoặc deployers...

---

## Template Usage Notes
Khi tạo PR fix false positive, copy template này và điền vào các sections:
1. **Required sections**: Tóm tắt, Vấn đề, Giải pháp, Testing, Impact Assessment
2. **Optional sections**: Screenshots/Logs, Additional Notes
3. **Checklists**: Đánh dấu [x] khi hoàn thành
4. **Metrics**: Điền số liệu thực tế (before/after)
5. **Test results**: Attach test output hoặc link đến CI results
