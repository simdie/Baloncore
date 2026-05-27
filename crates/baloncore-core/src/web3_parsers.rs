use crate::web3::*;
use std::path::Path;

fn parse_solidity_type(s: &str) -> SolidityType {
    SolidityType::from_str_lossy(s.trim())
}

fn parse_function_params(params_str: &str) -> Vec<SolidityParameter> {
    if params_str.trim().is_empty() {
        return Vec::new();
    }
    let mut result = Vec::new();
    for param in params_str.split(',') {
        let p = param.trim();
        if p.is_empty() {
            continue;
        }
        let parts: Vec<&str> = p.split_whitespace().collect();
        if parts.len() >= 2 {
            let is_indexed = parts.iter().any(|x| *x == "indexed");
            let type_only: Vec<&str> = parts
                .iter()
                .filter(|x| !matches!(**x, "indexed" | "memory" | "storage" | "calldata"))
                .copied()
                .collect();
            if type_only.len() >= 2 {
                result.push(SolidityParameter {
                    name: type_only[1].to_string(),
                    ty: parse_solidity_type(type_only[0]),
                    indexed: is_indexed,
                });
            } else if type_only.len() == 1 {
                result.push(SolidityParameter {
                    name: format!("_param_{}", result.len()),
                    ty: parse_solidity_type(type_only[0]),
                    indexed: is_indexed,
                });
            }
        } else if !p.is_empty() {
            result.push(SolidityParameter {
                name: format!("_param_{}", result.len()),
                ty: parse_solidity_type(p),
                indexed: false,
            });
        }
    }
    result
}

fn parse_function_header(
    line: &str,
) -> Option<(
    String,
    Vec<SolidityParameter>,
    FunctionVisibility,
    StateMutability,
    Vec<String>,
    bool,
)> {
    let line = line.trim();
    if !line.starts_with("function ") {
        return None;
    }
    let after_fn = &line[9..];
    let paren_start = after_fn.find('(')?;
    let name = after_fn[..paren_start].trim().to_string();
    let depth_chars: Vec<char> = after_fn[paren_start..].chars().collect();
    let mut depth = 0i32;
    let mut paren_end = paren_start;
    for (i, &ch) in depth_chars.iter().enumerate() {
        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                paren_end = paren_start + i;
                break;
            }
        }
    }
    let params_str = &after_fn[paren_start + 1..paren_end];
    let parameters = parse_function_params(params_str);

    let rest = after_fn.get(paren_end + 1..).unwrap_or("").trim();
    let mut visibility = FunctionVisibility::Public;
    let mut state_mutability = StateMutability::NonPayable;
    let mut modifiers = Vec::new();
    let mut is_payable = false;
    let mut remaining = rest.to_string();

    while !remaining.is_empty() {
        remaining = remaining.trim_start().to_string();
        if remaining.is_empty() {
            break;
        }
        if remaining.starts_with("public") {
            visibility = FunctionVisibility::Public;
            remaining = remaining[6..].trim_start().to_string();
        } else if remaining.starts_with("external") {
            visibility = FunctionVisibility::External;
            remaining = remaining[8..].trim_start().to_string();
        } else if remaining.starts_with("internal") {
            visibility = FunctionVisibility::Internal;
            remaining = remaining[8..].trim_start().to_string();
        } else if remaining.starts_with("private") {
            visibility = FunctionVisibility::Private;
            remaining = remaining[7..].trim_start().to_string();
        } else if remaining.starts_with("payable") {
            is_payable = true;
            state_mutability = StateMutability::Payable;
            remaining = remaining[7..].trim_start().to_string();
        } else if remaining.starts_with("view") && !remaining.starts_with("view_") {
            state_mutability = StateMutability::View;
            remaining = remaining[4..].trim_start().to_string();
        } else if remaining.starts_with("pure") && !remaining.starts_with("pure_") {
            state_mutability = StateMutability::Pure;
            remaining = remaining[4..].trim_start().to_string();
        } else if remaining.starts_with("virtual")
            || remaining.starts_with("override")
            || remaining.starts_with("returns")
        {
            let keyword = if remaining.starts_with("virtual") {
                "virtual"
            } else if remaining.starts_with("override") {
                "override"
            } else {
                "returns"
            };
            remaining = remaining[keyword.len()..].trim_start().to_string();
            if keyword == "returns" {
                break;
            }
        } else {
            let end = remaining
                .find(|c: char| c.is_whitespace() || c == '(' || c == '{' || c == ';')
                .unwrap_or(remaining.len());
            if end > 0 {
                let word = &remaining[..end];
                if !word.starts_with('{') && !word.starts_with(';') {
                    modifiers.push(word.to_string());
                }
                remaining = remaining[end..].trim_start().to_string();
                if remaining.starts_with("(") {
                    let mut d = 0i32;
                    let close = remaining.chars().enumerate().find(|(i, ch)| {
                        if *ch == '(' {
                            d += 1;
                        } else if *ch == ')' {
                            d -= 1;
                        }
                        d == 0 && *i > 0
                    });
                    if let Some((idx, _)) = close {
                        remaining = remaining[idx + 1..].trim_start().to_string();
                    }
                }
            } else {
                break;
            }
        }
    }
    Some((
        name,
        parameters,
        visibility,
        state_mutability,
        modifiers,
        is_payable,
    ))
}

fn parse_event_header(line: &str) -> Option<(String, Vec<SolidityParameter>)> {
    let line = line.trim();
    if !line.starts_with("event ") {
        return None;
    }
    let after = &line[6..];
    let paren_start = after.find('(')?;
    let name = after[..paren_start].trim().to_string();
    let paren_end = after.rfind(')')?;
    let params_str = &after[paren_start + 1..paren_end];
    Some((name, parse_function_params(params_str)))
}

fn parse_state_var(line: &str) -> Option<StorageVariable> {
    let line = line.trim().trim_end_matches(';').trim();
    if line.is_empty()
        || line.starts_with("//")
        || line.starts_with("/*")
        || line.starts_with("function ")
        || line.starts_with("event ")
        || line.starts_with("modifier ")
        || line.starts_with("constructor")
        || line.starts_with("receive")
        || line.starts_with("fallback")
        || line.starts_with("using ")
        || line.starts_with("struct ")
        || line.starts_with("enum ")
        || line.starts_with("error ")
        || line.starts_with("mapping(")
        || line.contains(" => ")
    {
        return None;
    }
    let mut visibility = FunctionVisibility::Private;
    let mut is_constant = false;
    let mut is_immutable = false;
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 2 {
        return None;
    }
    for t in &tokens {
        match *t {
            "public" => visibility = FunctionVisibility::Public,
            "private" => visibility = FunctionVisibility::Private,
            "internal" => visibility = FunctionVisibility::Internal,
            "external" => visibility = FunctionVisibility::External,
            "constant" => is_constant = true,
            "immutable" => is_immutable = true,
            _ => {}
        }
    }
    let filtered: Vec<&str> = tokens
        .iter()
        .filter(|t| {
            !matches!(
                **t,
                "public"
                    | "private"
                    | "internal"
                    | "external"
                    | "constant"
                    | "immutable"
                    | "override"
            )
        })
        .copied()
        .collect();
    if filtered.len() < 2 {
        return None;
    }
    Some(StorageVariable {
        name: filtered[1].to_string(),
        ty: parse_solidity_type(filtered[0]),
        visibility,
        is_constant,
        is_immutable,
        initial_value: None,
    })
}

fn strip_comments(source: &str) -> String {
    let mut result = String::new();
    let mut in_block = false;
    let mut chars = source.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_block {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block = false;
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            while let Some(&nc) = chars.peek() {
                if nc == '\n' {
                    break;
                }
                chars.next();
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            in_block = true;
            continue;
        }
        result.push(ch);
    }
    result
}

fn detect_contract_start(line: &str) -> Option<&str> {
    let l = line.trim();
    if l.starts_with("contract ")
        || l.starts_with("interface ")
        || l.starts_with("library ")
        || l.starts_with("abstract contract ")
    {
        Some(l)
    } else {
        None
    }
}

fn parse_contract_declaration(line: &str, file_path: &str) -> SolidityContract {
    let line = line.trim().trim_end_matches('{').trim();
    let kind = if line.starts_with("interface ") {
        ContractKind::Interface
    } else if line.starts_with("library ") {
        ContractKind::Library
    } else if line.starts_with("abstract ") {
        ContractKind::Abstract
    } else {
        ContractKind::Contract
    };
    let prefix = match kind {
        ContractKind::Interface => "interface ",
        ContractKind::Library => "library ",
        ContractKind::Abstract => "abstract contract ",
        ContractKind::Contract => "contract ",
    };
    let rest = line[prefix.len()..].trim();
    let name = rest
        .split_whitespace()
        .next()
        .unwrap_or("Unknown")
        .trim_end_matches('{')
        .to_string();
    let mut contract = SolidityContract::new(name, file_path.to_string()).with_kind(kind);
    if let Some(is_idx) = rest.find(" is ") {
        for parent in rest[is_idx + 4..].split(',') {
            let p = parent
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            if !p.is_empty() {
                contract = contract.with_inherits(p);
            }
        }
    }
    contract
}

pub fn parse_solidity_file(source: &str, file_path: &str) -> Vec<SolidityContract> {
    let source = strip_comments(source);
    let mut contracts: Vec<SolidityContract> = Vec::new();
    let mut current_contract_idx: Option<usize> = None;
    let mut brace_depth: usize = 0;

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("pragma ") || trimmed.starts_with("import ") {
            continue;
        }

        let opens = trimmed.chars().filter(|c| *c == '{').count();
        let closes = trimmed.chars().filter(|c| *c == '}').count();

        if current_contract_idx.is_none() {
            if detect_contract_start(trimmed).is_some() {
                let contract = parse_contract_declaration(trimmed, file_path);
                contracts.push(contract);
                current_contract_idx = Some(contracts.len() - 1);
                brace_depth = opens.saturating_sub(closes);
                continue;
            }
            continue;
        }

        let idx = current_contract_idx.unwrap();

        if trimmed.starts_with("event ") {
            if let Some((name, params)) = parse_event_header(trimmed) {
                let evt = params.into_iter().fold(SolidityEvent::new(name), |e, p| {
                    e.with_parameter(p.name, p.ty, p.indexed)
                });
                contracts[idx].events.push(evt);
            }
        } else if trimmed.starts_with("function ") {
            if let Some((name, params, vis, mutab, mods, payable)) = parse_function_header(trimmed)
            {
                let mut func = SolidityFunction::new(name)
                    .with_visibility(vis)
                    .with_state_mutability(mutab);
                if payable {
                    func = func.with_payable();
                }
                func.parameters = params;
                func.modifiers = mods;
                contracts[idx].functions.push(func);
            }
        } else if trimmed.starts_with("modifier ") {
            if let Some(mod_name) = trimmed.strip_prefix("modifier ") {
                let name = mod_name
                    .split('(')
                    .next()
                    .unwrap_or(mod_name)
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                contracts[idx].modifiers.push(name);
            }
        } else if !trimmed.contains("=>") {
            if let Some(v) = parse_state_var(trimmed) {
                contracts[idx].state_variables.push(v);
            }
        }

        brace_depth += opens;
        brace_depth = brace_depth.saturating_sub(closes);

        if brace_depth == 0 {
            current_contract_idx = None;
        }
    }

    for contract in &mut contracts {
        contract.detect_patterns();
    }
    contracts
}

pub fn parse_solidity_project(project_path: &str) -> Result<Web3Project, String> {
    let path = Path::new(project_path);
    if !path.exists() {
        return Err(format!("Project path does not exist: {}", project_path));
    }
    let kind = detect_project_kind(project_path);
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let mut project = Web3Project::new(&name, project_path, kind);

    if let Ok(foundry_toml) = std::fs::read_to_string(path.join("foundry.toml")) {
        project.foundry_config = Some(parse_foundry_config(&foundry_toml));
    }
    if let Some(hh_config) = parse_hardhat_config(path) {
        project.hardhat_config = Some(hh_config);
    }

    let src_dir = path.join("src");
    let contracts_dir = if src_dir.exists() {
        src_dir
    } else {
        path.to_path_buf()
    };
    let mut all_contracts: Vec<SolidityContract> = Vec::new();
    visit_solidity_files(&contracts_dir, &mut |file_path, source| {
        let file_name = file_path.to_string_lossy().to_string();
        all_contracts.extend(parse_solidity_file(source, &file_name));
    });

    for contract in all_contracts {
        project = project.with_contract(contract);
    }

    project.detect_all_patterns();
    Ok(project)
}

fn visit_solidity_files(dir: &Path, visitor: &mut dyn FnMut(&Path, &str)) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                visit_solidity_files(&path, visitor);
            } else if path.extension().and_then(|e| e.to_str()) == Some("sol") {
                if let Ok(source) = std::fs::read_to_string(&path) {
                    visitor(&path, &source);
                }
            }
        }
    }
}

pub fn parse_foundry_config(content: &str) -> FoundryConfig {
    let mut config = FoundryConfig::default_profile();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() || line.starts_with('[') {
            continue;
        }
        if let Some(eq_idx) = line.find('=') {
            let key = line[..eq_idx].trim();
            let value = line[eq_idx + 1..]
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            match key {
                "optimizer_runs" => {
                    if let Ok(r) = value.parse::<u32>() {
                        config.optimizer_runs = Some(r);
                    }
                }
                "evm_version" => config.evm_version = Some(value.to_string()),
                "solidity" | "solc_version" => config.solidity_version = Some(value.to_string()),
                "fuzz_runs" => {
                    if let Ok(r) = value.parse::<u32>() {
                        config.fuzz_runs = Some(r);
                    }
                }
                "invariant_runs" | "invariant.runs" => {
                    if let Ok(r) = value.parse::<u32>() {
                        config.invariant_runs = Some(r);
                    }
                }
                "timeout" => {
                    if let Ok(t) = value.parse::<u32>() {
                        config.timeout = Some(t);
                    }
                }
                _ => {}
            }
        }
    }
    config
}

fn parse_hardhat_config(project_path: &Path) -> Option<HardhatConfig> {
    let mut config = HardhatConfig::default_config();
    for config_file in &["hardhat.config.ts", "hardhat.config.js"] {
        let path = project_path.join(config_file);
        if let Ok(content) = std::fs::read_to_string(&path) {
            for line in content.lines() {
                let line = line.trim();
                if line.contains("solidity") {
                    let re = regex_lite::Regex::new(r#"solidity\s*[:=]\s*"([^"]+)""#).ok();
                    if let Some(caps) = re.and_then(|r| r.captures(line)) {
                        if let Some(v) = caps.get(1) {
                            config.solidity_version = Some(v.as_str().to_string());
                            return Some(config);
                        }
                    }
                }
            }
            return Some(config);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_contract() {
        let source = r#"
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 public storedValue;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function store(uint256 _value) public {
        storedValue = _value;
    }

    function retrieve() public view returns (uint256) {
        return storedValue;
    }

    function increment() external {
        storedValue = storedValue + 1;
    }
}
"#;
        let contracts = parse_solidity_file(source, "SimpleStorage.sol");
        assert_eq!(contracts.len(), 1);
        assert_eq!(contracts[0].name, "SimpleStorage");
        assert!(
            contracts[0].functions.len() >= 2,
            "Expected at least 2 functions, got {}",
            contracts[0].functions.len()
        );
        let store_fn = contracts[0]
            .functions
            .iter()
            .find(|f| f.name == "store")
            .unwrap();
        assert_eq!(store_fn.visibility, FunctionVisibility::Public);
        let retrieve_fn = contracts[0]
            .functions
            .iter()
            .find(|f| f.name == "retrieve")
            .unwrap();
        assert!(retrieve_fn.state_mutability.is_read_only());
    }

    #[test]
    fn test_parse_inheritance() {
        let source = r#"
pragma solidity ^0.8.0;

contract Ownable {
    address public owner;
}

contract Vault is Ownable {
    uint256 public totalShares;
    mapping(address => uint256) public balanceOf;

    function deposit() public payable {
    }

    function withdraw(uint256 shares) public {
    }
}
"#;
        let contracts = parse_solidity_file(source, "Vault.sol");
        assert_eq!(contracts.len(), 2);
        let vault = contracts.iter().find(|c| c.name == "Vault").unwrap();
        assert!(vault.inherits.contains(&"Ownable".to_string()));
        assert!(vault.functions.iter().any(|f| f.name == "deposit"));
    }

    #[test]
    fn test_parse_erc20_contract() {
        let source = r#"
pragma solidity ^0.8.0;

contract SimpleToken {
    string public name = "Simple";
    string public symbol = "SMP";
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function transfer(address to, uint256 amount) public returns (bool) {
    }

    function approve(address spender, uint256 amount) public returns (bool) {
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
    }
}
"#;
        let contracts = parse_solidity_file(source, "SimpleToken.sol");
        assert_eq!(contracts.len(), 1);
        let contract = &contracts[0];
        let transfer_fn = contract.functions.iter().find(|f| f.name == "transfer");
        assert!(transfer_fn.is_some(), "Should find transfer function");
        let approve_fn = contract.functions.iter().find(|f| f.name == "approve");
        assert!(approve_fn.is_some(), "Should find approve function");
    }

    #[test]
    fn test_parse_interface() {
        let source = r#"
pragma solidity ^0.8.0;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}
"#;
        let contracts = parse_solidity_file(source, "IERC20.sol");
        assert_eq!(contracts.len(), 1);
        assert_eq!(contracts[0].kind, ContractKind::Interface);
        assert_eq!(contracts[0].name, "IERC20");
    }

    #[test]
    fn test_parse_payable_function() {
        let source = r#"
pragma solidity ^0.8.0;

contract DepositContract {
    function deposit() public payable {
    }

    function withdraw(uint256 amount) public {
    }
}
"#;
        let contracts = parse_solidity_file(source, "DepositContract.sol");
        let deposit_fn = contracts[0]
            .functions
            .iter()
            .find(|f| f.name == "deposit")
            .unwrap();
        assert!(deposit_fn.is_payable);
        assert_eq!(deposit_fn.state_mutability, StateMutability::Payable);
    }

    #[test]
    fn test_parse_upgradeable_contract() {
        let source = r#"
pragma solidity ^0.8.0;

contract UpgradeableVault is Initializable, UUPSUpgradeable {
    uint256 public totalShares;

    function initialize() public initializer {
        totalShares = 0;
    }

    function deposit() public payable {
    }
}
"#;
        let mut contracts = parse_solidity_file(source, "UpgradeableVault.sol");
        assert_eq!(contracts.len(), 1);
        contracts[0].detect_patterns();
        assert!(contracts[0].is_upgradeable);
    }

    #[test]
    fn test_detect_project_kind_foundry_config() {
        let tmp_dir = std::env::temp_dir().join("baloncore_test_web3_foundry2");
        let _ = std::fs::create_dir_all(&tmp_dir);
        let _ = std::fs::write(
            tmp_dir.join("foundry.toml"),
            "[profile.default]\nsrc = 'src'\noptimizer_runs = 200\nsolidity = '0.8.19'\n",
        );
        let kind = detect_project_kind(tmp_dir.to_str().unwrap());
        assert_eq!(kind, Web3ProjectKind::Foundry);
        let config = parse_foundry_config(
            "[profile.default]\nsrc = 'src'\noptimizer_runs = 200\nsolidity = '0.8.19'\n",
        );
        assert_eq!(config.optimizer_runs, Some(200));
        assert_eq!(config.solidity_version, Some("0.8.19".to_string()));
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[test]
    fn test_parse_solidity_type() {
        assert_eq!(parse_solidity_type("uint256"), SolidityType::Uint256);
        assert_eq!(parse_solidity_type("address"), SolidityType::Address);
        assert_eq!(parse_solidity_type("bool"), SolidityType::Bool);
    }

    #[test]
    fn test_full_analysis_pipeline() {
        let mut project = Web3Project::new(
            "vuln-token",
            "/path/to/vuln-token",
            Web3ProjectKind::Foundry,
        );
        let contract = SolidityContract::new("VulnToken", "VulnToken.sol")
            .with_function(
                SolidityFunction::new("transfer")
                    .with_visibility(FunctionVisibility::Public)
                    .with_parameter("to", SolidityType::Address)
                    .with_parameter("amount", SolidityType::Uint256)
                    .with_return_type(SolidityType::Bool),
            )
            .with_function(
                SolidityFunction::new("approve")
                    .with_visibility(FunctionVisibility::Public)
                    .with_parameter("spender", SolidityType::Address)
                    .with_parameter("amount", SolidityType::Uint256)
                    .with_return_type(SolidityType::Bool),
            )
            .with_function(SolidityFunction::new("deposit").with_payable());

        project = project.with_contract(contract);
        project.detect_all_patterns();

        let result = analyze_web3_project(&mut project);
        assert!(result.findings.len() > 0, "Expected at least one finding");
        assert!(result.invariants.len() > 0, "Expected invariants");
    }

    #[test]
    fn test_strip_comments() {
        let source =
            "pragma solidity ^0.8.0;\n// comment\ncontract Foo {\n/* block */\nuint256 x;\n}";
        let stripped = strip_comments(source);
        assert!(!stripped.contains("// comment"));
        assert!(stripped.contains("contract Foo"));
        assert!(stripped.contains("uint256 x"));
    }

    #[test]
    fn test_slither_severity_mapping() {
        let finding = SlitherFinding {
            detector: "reentrancy-eth".to_string(),
            severity: "High".to_string(),
            confidence: "Medium".to_string(),
            description: "Test".to_string(),
            first_markdown_line: None,
            elements: vec![],
        };
        assert_eq!(finding.to_web3_severity(), Web3Severity::High);
    }
}
