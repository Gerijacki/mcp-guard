package rules

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/Gerijacki/mcp-guard/internal/finding"
	"github.com/Gerijacki/mcp-guard/internal/source"
)

// MCPG011: an MCP client config launches third-party code in a way that cannot be reviewed
// or pinned (unversioned npx/uvx/docker, remote scripts, privileged containers, plain http).
type supplyChainRule struct{}

var (
	// "pkg@1.2.3", "@scope/pkg@^1.2", "pkg==1.2.3": a concrete version.
	pinnedVersionRe = regexp.MustCompile(`(?:@|==|===)[v~^]?\d[\w.+\-]*$`)
	remoteScriptRe  = regexp.MustCompile(`(?i)\b(?:curl|wget|iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b[^|;&]*[|]\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|]*\|\s*iex\b|\b(?:bash|sh)\s+<\(\s*(?:curl|wget)`)
	// docker run flags that take a value, so the value is not mistaken for the image.
	dockerValueFlags = map[string]bool{
		"-e": true, "--env": true, "-v": true, "--volume": true, "-p": true, "--publish": true,
		"--name": true, "--network": true, "--net": true, "--mount": true, "-w": true, "--workdir": true,
		"-u": true, "--user": true, "--entrypoint": true, "--platform": true, "--env-file": true,
		"--label": true, "-l": true, "--add-host": true, "--memory": true, "-m": true, "--cpus": true,
		"--restart": true, "--pull": true, "--cap-add": true, "--cap-drop": true, "--security-opt": true,
	}
)

func (supplyChainRule) Meta() Meta {
	return Meta{
		ID:       "MCPG011",
		Name:     "unpinned-or-risky-server-launch",
		Severity: finding.Medium,
		Summary:  "MCP client config runs unpinned packages, remote scripts or privileged containers",
		Description: "An MCP client configuration launches a server with `npx`, `uvx` or `docker run` without " +
			"pinning a version or digest, pipes a downloaded script into a shell, runs a privileged container " +
			"or mounts the Docker socket or the host root, or talks to a remote server over plain http. " +
			"Every launch then executes whatever the package registry or network serves at that moment, so a " +
			"compromised or typosquatted release (or a man in the middle) runs with the user's privileges " +
			"and the credentials in the config.",
		Remediation: "Pin the version (`npx -y pkg@1.2.3`, `uvx pkg==1.2.3`, an image tag or `@sha256:` digest) and " +
			"update it deliberately. Review a package before adding it, prefer servers you can audit, never " +
			"pipe curl into a shell, drop `--privileged` and host mounts, and use https for remote servers.",
		CWE:   []string{"CWE-1357", "CWE-829", "CWE-319"},
		OWASP: []string{"MCP04:2025", "LLM03:2025", "ASI04:2026"},
	}
}

func (r supplyChainRule) Check(f *source.File) []finding.Finding {
	var out []finding.Finding
	for _, s := range f.Servers {
		add := func(sev finding.Severity, msg string) {
			out = append(out, newFinding(r.Meta(), f, s.Line, sev, "", fmt.Sprintf("MCP server %q %s.", s.Name, msg)))
		}
		cmd := strings.ToLower(path.Base(strings.ReplaceAll(s.Command, `\`, "/")))
		cmd = strings.TrimSuffix(strings.TrimSuffix(cmd, ".cmd"), ".exe")
		args := s.Args

		switch cmd {
		case "npx", "bunx", "pnpx":
			addUnpinned(add, "npm package", firstPackageArg(args, nil))
		case "pnpm", "yarn", "bun":
			if len(args) > 0 && (args[0] == "dlx" || args[0] == "x") {
				addUnpinned(add, "npm package", firstPackageArg(args[1:], nil))
			}
		case "uvx":
			addUnpinned(add, "Python package", pythonPackage(args))
		case "pipx":
			if len(args) > 0 && args[0] == "run" {
				addUnpinned(add, "Python package", pythonPackage(args[1:]))
			}
		case "uv":
			if len(args) > 1 && args[0] == "tool" && args[1] == "run" {
				addUnpinned(add, "Python package", pythonPackage(args[2:]))
			}
		case "docker", "podman":
			checkDocker(add, args)
		case "sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh":
			if remoteScriptRe.MatchString(strings.Join(args, " ")) {
				add(finding.High, "downloads a script and pipes it into a shell on every launch")
			}
		}
		if remoteScriptRe.MatchString(s.Command) {
			add(finding.High, "downloads a script and pipes it into a shell on every launch")
		}
		if u, err := url.Parse(s.URL); err == nil && u.Scheme == "http" && !isLocalHost(u.Hostname()) && !strings.ContainsAny(u.Host, "${}") {
			add(finding.Medium, fmt.Sprintf("connects to %s over plain http: tokens and tool traffic are readable and modifiable on the network", u.Host))
		}
	}
	return out
}

func addUnpinned(add func(finding.Severity, string), kind, pkg string) {
	if pkg == "" || strings.HasPrefix(pkg, ".") || strings.HasPrefix(pkg, "/") || strings.Contains(pkg, "://") ||
		strings.HasPrefix(pkg, "file:") || strings.HasPrefix(pkg, "github:") || strings.HasPrefix(pkg, "git+") || strings.HasPrefix(pkg, "~") {
		return
	}
	switch {
	case strings.HasSuffix(pkg, "@latest"):
		add(finding.Medium, fmt.Sprintf("runs the %s %q at @latest: every launch can pick up a new, unreviewed release", kind, pkg))
	case !pinnedVersionRe.MatchString(pkg):
		add(finding.Low, fmt.Sprintf("runs the %s %q without a pinned version: every launch fetches whatever the registry serves", kind, pkg))
	}
}

// firstPackageArg returns the first argument that is not a flag (npx -y pkg --port 1 -> pkg).
func firstPackageArg(args []string, valueFlags map[string]bool) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if valueFlags[a] {
				i++
			}
			if a == "-p" || a == "--package" { // npx -p pkg cmd: the package is the flag value
				if i+1 < len(args) {
					return args[i+1]
				}
			}
			continue
		}
		return a
	}
	return ""
}

// pythonPackage handles `uvx pkg`, `uvx --from pkg tool` and `pipx run --spec pkg tool`.
func pythonPackage(args []string) string {
	for i, a := range args {
		if (a == "--from" || a == "--spec") && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(a, "--from=") || strings.HasPrefix(a, "--spec=") {
			return a[strings.IndexByte(a, '=')+1:]
		}
	}
	return firstPackageArg(args, map[string]bool{"--python": true, "-p": true, "--with": true, "--index-url": true})
}

func checkDocker(add func(finding.Severity, string), args []string) {
	if len(args) == 0 || args[0] != "run" {
		return
	}
	var image string
	for i := 1; i < len(args); i++ {
		a := args[i]
		flag, val := a, ""
		if eq := strings.IndexByte(a, '='); eq > 0 && strings.HasPrefix(a, "--") {
			flag, val = a[:eq], a[eq+1:]
		} else if dockerValueFlags[a] && i+1 < len(args) {
			val = args[i+1]
		}
		switch {
		case flag == "--privileged":
			add(finding.High, "runs its container with --privileged (full access to the host)")
		case flag == "--cap-add" && (strings.EqualFold(val, "ALL") || strings.EqualFold(val, "SYS_ADMIN")):
			add(finding.High, fmt.Sprintf("adds the %s capability to its container", strings.ToUpper(val)))
		case (flag == "--network" || flag == "--net") && val == "host":
			add(finding.Medium, "shares the host network with its container")
		case (flag == "--pid" || flag == "--ipc") && val == "host":
			add(finding.High, fmt.Sprintf("shares the host %s namespace with its container", strings.TrimPrefix(flag, "--")))
		case flag == "-v" || flag == "--volume" || flag == "--mount":
			if strings.Contains(val, "docker.sock") {
				add(finding.High, "mounts the Docker socket into its container (equivalent to root on the host)")
			} else if v := strings.SplitN(strings.TrimPrefix(val, "type=bind,"), ":", 2); (flag != "--mount" && (v[0] == "/" || v[0] == "~")) || strings.Contains(val, "source=/,") || strings.HasSuffix(val, "source=/") {
				add(finding.High, "mounts the host root or home directory into its container")
			}
		}
		if strings.HasPrefix(a, "-") {
			if dockerValueFlags[a] {
				i++
			}
			continue
		}
		image = a
		break
	}
	if image == "" || strings.Contains(image, "@sha256:") {
		return
	}
	name := image[strings.LastIndexByte(image, '/')+1:]
	switch {
	case !strings.Contains(name, ":"):
		add(finding.Low, fmt.Sprintf("runs the Docker image %q without a tag: it resolves to :latest on every pull", image))
	case strings.HasSuffix(name, ":latest"):
		add(finding.Low, fmt.Sprintf("runs the Docker image %q at :latest: every pull can bring a new, unreviewed release", image))
	}
}

func isLocalHost(h string) bool {
	h = strings.ToLower(h)
	return h == "localhost" || h == "::1" || h == "0.0.0.0" || strings.HasPrefix(h, "127.") || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local")
}
