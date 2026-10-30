# 🛡️ Shield Rules

Autonomous, validated IP prefix lists and update workflows for network edge protection on `just1knode` foreign servers.

---

## Files

* **`rkn.txt`**: Consolidated IPv4 prefix list of Russian regulators (GRCHC, CMU SSOP, RKN) and known active probe networks. Used on foreign VLESS servers in `iptables INPUT` (`DROP`) to prevent L7 active protocol probing.
* **`vk.txt`**: Consolidated IPv4 prefix list of VK Company, Odnoklassniki, Mail.ru, and Messenger Max services. Used on foreign VLESS servers in `iptables FORWARD` and `OUTPUT` (`REJECT with tcp-reset`) to prevent node de-anonymization via Russian telemetry.

---

## Automation

Lists are updated automatically via GitHub Actions twice a week (`.github/workflows/update.yml`) using `builder/build.py`.  
Overlapping networks are collapsed and private/bogon subnets are strictly excluded.
