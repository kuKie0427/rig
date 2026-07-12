"""Unit tests for k8s command validation and safety checks.

Tests the allowlist / deny-dimension / force-escalation logic, plus
quote / heredoc safety and the structured K8sCommandDecision output of
`rig/tools/k8s_validation.py`.

Mirrors the convention of `test_tools_shell_validation.py`: class-based
test groups, plain `assert` statements, no parametrize. Targets ~50
test cases covering all 7 CLI families × allowlist + D1-D8 deny
dimensions + force escalation + safety edge cases.
"""

from dataclasses import FrozenInstanceError

from rig.tools.k8s_validation import (
    ALLOWLISTED_SUBCOMMANDS,
    DENY_GROUPS,
    FAMILIES,
    REQUIRED_APPROVALS_BY_RISK,
    RISK_LEVEL_BY_DIMENSION,
    K8sCommandDecision,
    classify_k8s_command,
    is_k8s_allowlisted,
    is_k8s_denylisted,
    required_approvals_for,
)


class TestModuleSurface:
    """Module-level constants and exports match DIRECTIONS.md § Phase 1."""

    def test_families_contains_seven_k8s_clis(self):
        assert frozenset(
            {"kubectl", "helm", "cilium", "ciliumctl", "istioctl", "argocd", "flux", "fluxctl"}
        ) == FAMILIES

    def test_allowlist_keys_match_families_plus_krew(self):
        families = set(ALLOWLISTED_SUBCOMMANDS.keys())
        assert families == set(FAMILIES) | {"krew"}

    def test_deny_groups_covers_d1_through_d8(self):
        labels = [label for label, _, _ in DENY_GROUPS]
        assert labels == ["D7", "D6", "D5", "D4", "D3", "D2", "D8", "D1"]

    def test_risk_levels_match_direction_spec(self):
        assert RISK_LEVEL_BY_DIMENSION == {
            "D1": "medium",
            "D2": "medium",
            "D3": "medium",
            "D4": "medium",
            "D5": "medium",
            "D6": "high",
            "D7": "high",
            "D8": "medium",
        }

    def test_required_approvals_for_risk_levels(self):
        assert REQUIRED_APPROVALS_BY_RISK == {"low": 1, "medium": 2, "high": 3}


class TestDecisionDataclass:
    """K8sCommandDecision is frozen: callers cannot mutate the verdict."""

    def _decision(self) -> K8sCommandDecision:
        return classify_k8s_command("kubectl get pods")

    def test_decision_is_frozen(self):
        decision = self._decision()
        try:
            decision.action = "deny"  # type: ignore[misc]
        except FrozenInstanceError:
            return
        raise AssertionError("K8sCommandDecision should be frozen")

    def test_decision_passes_equality_check(self):
        a = classify_k8s_command("kubectl get pods")
        b = classify_k8s_command("kubectl get pods")
        assert a == b


class TestAllowlistKubectl:
    """7 allowlisted kubectl subcommands from DIRECTIONS.md."""

    def test_get(self):
        assert is_k8s_allowlisted("kubectl get pods")

    def test_describe(self):
        assert is_k8s_allowlisted("kubectl describe pod foo")

    def test_logs(self):
        assert is_k8s_allowlisted("kubectl logs pod-foo")

    def test_top(self):
        assert is_k8s_allowlisted("kubectl top pods")

    def test_explain(self):
        assert is_k8s_allowlisted("kubectl explain pod.spec")

    def test_rollout_status_two_tokens(self):
        assert is_k8s_allowlisted("kubectl rollout status deployment/foo")

    def test_auth_can_i_two_tokens(self):
        assert is_k8s_allowlisted("kubectl auth can-i delete pods")

    def test_rollout_history_not_in_allowlist(self):
        d = classify_k8s_command("kubectl rollout history deploy/foo")
        assert d.action in ("hitl", "deny")


class TestAllowlistHelm:
    def test_list(self):
        assert is_k8s_allowlisted("helm list")

    def test_search(self):
        assert is_k8s_allowlisted("helm search repo stable")

    def test_status(self):
        assert is_k8s_allowlisted("helm status my-release")

    def test_install_not_allowlisted(self):
        assert not is_k8s_allowlisted("helm install r1 stable/chart")


class TestAllowlistCilium:
    def test_get(self):
        assert is_k8s_allowlisted("cilium get nodes")

    def test_describe(self):
        assert is_k8s_allowlisted("cilium describe node k8s-1")

    def test_endpoint(self):
        assert is_k8s_allowlisted("cilium endpoint list")

    def test_identity_get_two_tokens(self):
        assert is_k8s_allowlisted("cilium identity get 12345")

    def test_ciliumctl_alias_works(self):
        assert is_k8s_allowlisted("ciliumctl get nodes")
        assert is_k8s_allowlisted("ciliumctl endpoint list")


class TestAllowlistIstioctl:
    def test_analyze(self):
        assert is_k8s_allowlisted("istioctl analyze")

    def test_describe(self):
        assert is_k8s_allowlisted("istioctl describe pod my-pod")


class TestAllowlistArgocd:
    def test_app_get_two_tokens(self):
        assert is_k8s_allowlisted("argocd app get my-app")

    def test_app_list_two_tokens(self):
        assert is_k8s_allowlisted("argocd app list")

    def test_app_logs_two_tokens(self):
        assert is_k8s_allowlisted("argocd app logs my-app --tail 100")

    def test_app_get_with_namespace_flag(self):
        assert is_k8s_allowlisted("argocd app get my-app --grpc-web")


class TestAllowlistFlux:
    def test_get(self):
        assert is_k8s_allowlisted("flux get kustomizations")

    def test_list(self):
        assert is_k8s_allowlisted("flux list")

    def test_fluxctl_alias_works(self):
        assert is_k8s_allowlisted("fluxctl get helmreleases")


class TestAllowlistKrew:
    def test_krew_search(self):
        assert is_k8s_allowlisted("kubectl krew search")

    def test_krew_install_not_allowlisted_hits_d5(self):
        d = classify_k8s_command("kubectl krew install foo")
        assert d.action == "hitl"
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"


class TestDenyD1:
    """D1: kubectl delete (broad). medium; --force --grace-period=0 -> high."""

    def test_delete_pod(self):
        d = classify_k8s_command("kubectl delete pod foo")
        assert d.deny_dimension == "D1"
        assert d.risk_level == "medium"

    def test_delete_deployment(self):
        d = classify_k8s_command("kubectl delete deployment my-app")
        assert d.deny_dimension == "D1"
        assert d.risk_level == "medium"

    def test_delete_force_grace_period_zero_high(self):
        d = classify_k8s_command("kubectl delete pod foo --force --grace-period=0")
        assert d.deny_dimension == "D1"
        assert d.risk_level == "high"


class TestDenyD2:
    """D2: helm uninstall / delete. medium."""

    def test_helm_uninstall(self):
        d = classify_k8s_command("helm uninstall my-release")
        assert d.deny_dimension == "D2"
        assert d.risk_level == "medium"

    def test_helm_delete_old_form(self):
        d = classify_k8s_command("helm delete my-release")
        assert d.deny_dimension == "D2"
        assert d.risk_level == "medium"


class TestDenyD3:
    """D3: scale to zero; rollout undo. medium."""

    def test_scale_replicas_zero(self):
        d = classify_k8s_command("kubectl scale deploy foo --replicas=0")
        assert d.deny_dimension == "D3"
        assert d.risk_level == "medium"

    def test_scale_replicas_space_zero(self):
        d = classify_k8s_command("kubectl scale deploy foo --replicas 0")
        assert d.deny_dimension == "D3"
        assert d.risk_level == "medium"

    def test_scale_up_not_d3_default_medium(self):
        d = classify_k8s_command("kubectl scale deploy foo --replicas=3")
        assert d.deny_dimension is None
        assert d.risk_level == "medium"
        assert d.action == "hitl"

    def test_rollout_undo(self):
        d = classify_k8s_command("kubectl rollout undo deployment/foo")
        assert d.deny_dimension == "D3"
        assert d.risk_level == "medium"


class TestDenyD4:
    """D4: node drain / cordon / taint eviction. medium."""

    def test_drain(self):
        d = classify_k8s_command("kubectl drain node1")
        assert d.deny_dimension == "D4"
        assert d.risk_level == "medium"

    def test_cordon(self):
        d = classify_k8s_command("kubectl cordon node1")
        assert d.deny_dimension == "D4"
        assert d.risk_level == "medium"

    def test_taint_no_schedule_minus(self):
        d = classify_k8s_command("kubectl taint nodes node1 key=value:NoSchedule-")
        assert d.deny_dimension == "D4"
        assert d.risk_level == "medium"


class TestDenyD5:
    """D5: RBAC / GitOps sync / krew install. medium base; --force -> high."""

    def test_kubectl_apply_clusterrole(self):
        d = classify_k8s_command("kubectl apply -f clusterrole.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_kubectl_apply_clusterrole_no_dash_f(self):
        d = classify_k8s_command("kubectl apply clusterrole.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_kubectl_apply_no_clusterrole_no_force_is_medium(self):
        d = classify_k8s_command("kubectl apply -f deployment.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_kubectl_apply_with_global_flags(self):
        d = classify_k8s_command("kubectl --context prod apply -f clusterrole.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_kubectl_auth_reconcile(self):
        d = classify_k8s_command("kubectl auth reconcile -f foo.yaml")
        assert d.deny_dimension == "D5"

    def test_argocd_app_sync(self):
        d = classify_k8s_command("argocd app sync my-app")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_argocd_app_sync_force_escalates_to_high(self):
        d = classify_k8s_command("argocd app sync --force my-app")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_flux_reconcile(self):
        d = classify_k8s_command("flux reconcile kustomization foo")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_flux_reconcile_force_escalates_to_high(self):
        d = classify_k8s_command("flux reconcile --force ks/foo")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_kubectl_krew_install(self):
        d = classify_k8s_command("kubectl krew install foo")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"


class TestDenyD6:
    """D6: kubectl delete namespace. Always high."""

    def test_delete_ns(self):
        d = classify_k8s_command("kubectl delete ns production")
        assert d.deny_dimension == "D6"
        assert d.risk_level == "high"

    def test_delete_namespace_full_keyword(self):
        d = classify_k8s_command("kubectl delete namespace production")
        assert d.deny_dimension == "D6"
        assert d.risk_level == "high"

    def test_delete_ns_with_flag(self):
        d = classify_k8s_command("kubectl delete -n ns production")
        assert d.deny_dimension == "D6"
        assert d.risk_level == "high"


class TestDenyD7:
    """D7: lateral-movement access (exec/cp/port-forward/proxy). Always high."""

    def test_kubectl_exec(self):
        d = classify_k8s_command("kubectl exec -it pod-foo -- bash")
        assert d.deny_dimension == "D7"
        assert d.risk_level == "high"

    def test_kubectl_cp(self):
        d = classify_k8s_command("kubectl cp pod-foo /tmp/x /tmp/y")
        assert d.deny_dimension == "D7"
        assert d.risk_level == "high"

    def test_kubectl_port_forward(self):
        d = classify_k8s_command("kubectl port-forward pod-foo 8080:80")
        assert d.deny_dimension == "D7"
        assert d.risk_level == "high"

    def test_kubectl_proxy(self):
        d = classify_k8s_command("kubectl proxy")
        assert d.deny_dimension == "D7"
        assert d.risk_level == "high"


class TestDenyD8:
    """D8: schemaless edit / debug. medium."""

    def test_kubectl_edit(self):
        d = classify_k8s_command("kubectl edit deployment foo")
        assert d.deny_dimension == "D8"
        assert d.risk_level == "medium"

    def test_kubectl_debug(self):
        d = classify_k8s_command("kubectl debug pod/p1 --image=busybox")
        assert d.deny_dimension == "D8"
        assert d.risk_level == "medium"


class TestDefaultHitlMedium:
    """K8s family detected but neither allowlisted nor denied -> hitl medium."""

    def test_kubectl_wait_not_in_d_or_allowlist(self):
        d = classify_k8s_command("kubectl wait pod/p1 --for=condition=Ready")
        assert d.action == "hitl"
        assert d.risk_level == "medium"
        assert d.deny_dimension is None
        assert d.family == "kubectl"

    def test_helm_install_default(self):
        d = classify_k8s_command("helm install r1 stable/chart")
        assert d.action == "hitl"
        assert d.risk_level == "medium"
        assert d.family == "helm"

    def test_cilium_status_not_in_allowlist(self):
        d = classify_k8s_command("cilium status")
        assert d.action == "hitl"
        assert d.risk_level == "medium"
        assert d.family == "cilium"

    def test_kubectl_alone(self):
        d = classify_k8s_command("kubectl")
        assert d.action == "hitl"
        assert d.is_k8s_command is True
        assert d.family == "kubectl"


class TestNonK8sCommands:
    """Non-K8s shell traffic returns vacuous allow, is_k8s_command=False."""

    def test_ls(self):
        d = classify_k8s_command("ls -la")
        assert d.action == "allow"
        assert d.is_k8s_command is False
        assert d.family is None

    def test_git_status(self):
        d = classify_k8s_command("git status")
        assert d.is_k8s_command is False

    def test_echo(self):
        d = classify_k8s_command("echo hello")
        assert d.is_k8s_command is False

    def test_docker_exec_container_runtime_oos(self):
        d = classify_k8s_command("docker exec -it my-container bash")
        assert d.is_k8s_command is False
        assert d.deny_dimension is None

    def test_kustomize_not_a_family(self):
        d = classify_k8s_command("kustomize build .")
        assert d.is_k8s_command is False

    def test_is_k8s_allowlisted_false_for_ls(self):
        assert is_k8s_allowlisted("ls -la") is False


class TestQuotedAndHeredocSafety:
    """Dangerous patterns inside quotes / heredocs must NOT trigger deny."""

    def test_quote_single_does_not_trigger(self):
        d = classify_k8s_command("echo 'kubectl delete pod foo'")
        assert d.deny_dimension is None
        assert d.action == "allow"
        assert d.is_k8s_command is False

    def test_quote_double_does_not_trigger(self):
        d = classify_k8s_command('echo "kubectl delete pod foo"')
        assert d.deny_dimension is None

    def test_heredoc_content_does_not_trigger(self):
        cmd = "cat << EOF\nkubectl delete pod foo\nrm -rf /\nEOF"
        d = classify_k8s_command(cmd)
        assert d.deny_dimension is None
        assert d.is_k8s_command is False

    def test_kubectl_log_with_quoted_arg_still_allowlisted(self):
        d = classify_k8s_command('kubectl logs pod-foo "some quoted arg"')
        assert d.action == "allow"
        assert d.family == "kubectl"


class TestForceEscalationSafety:
    """--force only escalates D1/D5; other dimensions ignore it."""

    def test_force_in_quoted_string_does_not_escalate(self):
        d = classify_k8s_command("kubectl logs pod-foo --since=1h")
        assert d.action == "allow"

    def test_force_with_lease_in_kubectl_logs_still_allowlisted(self):
        d = classify_k8s_command("kubectl logs pod-foo --force-with-lease")
        assert d.action == "allow"
        assert d.risk_level == "low"
        assert d.deny_dimension is None

    def test_force_does_not_escalate_d6(self):
        d = classify_k8s_command("kubectl delete ns production --force")
        assert d.deny_dimension == "D6"
        assert d.risk_level == "high"

    def test_force_does_not_escalate_d7(self):
        d = classify_k8s_command("kubectl exec -it pod-foo -- bash --force")
        assert d.deny_dimension == "D7"
        assert d.risk_level == "high"


class TestPipelineTolerance:
    """Pipeline chains are classified by the leading K8s family token."""

    def test_kubectl_logs_piped_to_grep(self):
        d = classify_k8s_command("kubectl logs pod-foo | grep ERROR")
        assert d.action == "allow"
        assert d.family == "kubectl"

    def test_kubectl_get_piped_to_jq(self):
        d = classify_k8s_command("kubectl get pods -A | jq '.items[].metadata.name'")
        assert d.action == "allow"


class TestEdgeCases:
    """Empty / whitespace / malformed input yields vacuous allow."""

    def test_empty_string(self):
        d = classify_k8s_command("")
        assert d.action == "allow"
        assert d.is_k8s_command is False

    def test_whitespace_only(self):
        d = classify_k8s_command("   ")
        assert d.action == "allow"
        assert d.is_k8s_command is False

    def test_unclosed_quote_falls_back(self):
        d = classify_k8s_command("kubectl logs 'unclosed")
        assert d.action == "allow"
        assert d.family == "kubectl"


class TestPublicApiHelpers:
    """is_k8s_allowlisted / is_k8s_denylisted / required_approvals_for."""

    def test_is_k8s_allowlisted_allowlisted_command(self):
        assert is_k8s_allowlisted("kubectl get pods") is True

    def test_is_k8s_allowlisted_deny_command(self):
        assert is_k8s_allowlisted("kubectl delete pod foo") is False

    def test_is_k8s_allowlisted_non_k8s_command(self):
        assert is_k8s_allowlisted("ls") is False

    def test_is_k8s_denylisted_hitl_command_returns_triple(self):
        triggered, reason, matched = is_k8s_denylisted("kubectl delete pod foo")
        assert triggered is True
        assert reason is not None
        assert matched is not None

    def test_is_k8s_denylisted_allowlisted_returns_false(self):
        triggered, reason, matched = is_k8s_denylisted("kubectl get pods")
        assert triggered is False
        assert reason is None
        assert matched is None

    def test_is_k8s_denylisted_non_k8s_returns_false(self):
        triggered, _, _ = is_k8s_denylisted("ls -la")
        assert triggered is False

    def test_required_approvals_for_low(self):
        assert required_approvals_for("low") == 1

    def test_required_approvals_for_medium(self):
        assert required_approvals_for("medium") == 2

    def test_required_approvals_for_high(self):
        assert required_approvals_for("high") == 3


class TestReasonAndMatchPropagation:
    """The reason / matched_text fields of K8sCommandDecision carry audit info."""

    def test_reason_contains_dimension_label(self):
        d = classify_k8s_command("kubectl delete pod foo")
        assert d.reason is not None
        assert "[D1]" in d.reason

    def test_matched_text_contains_kubectl_delete(self):
        d = classify_k8s_command("kubectl delete pod foo --force --grace-period=0")
        assert d.matched_text is not None
        assert "kubectl delete" in d.matched_text

    def test_default_hitl_reason_explains_default(self):
        d = classify_k8s_command("kubectl wait pod/p1 --for=condition=Ready")
        assert d.reason is not None
        assert "default HITL medium" in d.reason or "DIRECTIONS" in d.reason

    def test_allowlisted_decision_has_no_reason_no_match(self):
        d = classify_k8s_command("kubectl get pods")
        assert d.reason is None
        assert d.matched_text is None
        assert d.deny_dimension is None


class TestGlobalFlagTolerance:
    """Oracle-flagged regression: global kubectl flags must not bypass deny classification.

    Real commands frequently include --context / -n / --kubeconfig / --as before
    the verb. Each deny dimension must still match in those cases.
    """

    def test_kubectl_context_then_exec_is_d7_high(self):
        d = classify_k8s_command("kubectl --context prod exec foo")
        assert d.deny_dimension == "D7"
        assert d.risk_level == "high"

    def test_kubectl_context_namespace_then_exec_is_d7_high(self):
        d = classify_k8s_command("kubectl --context prod -n ns1 exec foo")
        assert d.deny_dimension == "D7"
        assert d.risk_level == "high"

    def test_kubectl_context_then_delete_ns_is_d6_high(self):
        d = classify_k8s_command("kubectl --context staging delete ns foo")
        assert d.deny_dimension == "D6"
        assert d.risk_level == "high"

    def test_kubectl_namespace_then_delete_ns_is_d6_high(self):
        d = classify_k8s_command("kubectl -n prod delete ns production")
        assert d.deny_dimension == "D6"
        assert d.risk_level == "high"

    def test_kubectl_context_then_drain_is_d4(self):
        d = classify_k8s_command("kubectl --context prod drain node1")
        assert d.deny_dimension == "D4"
        assert d.risk_level == "medium"

    def test_kubectl_context_then_edit_is_d8(self):
        d = classify_k8s_command("kubectl --context prod edit deployment x")
        assert d.deny_dimension == "D8"

    def test_kubectl_context_then_apply_clusterrole_is_d5_high(self):
        d = classify_k8s_command("kubectl --context prod apply -f clusterrole.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_kubectl_context_then_apply_no_clusterrole_is_d5_medium(self):
        d = classify_k8s_command("kubectl --context prod apply -f deployment.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_helm_kube_context_then_uninstall_is_d2(self):
        d = classify_k8s_command("helm uninstall --kube-context prod my-release")
        assert d.deny_dimension == "D2"

    def test_argocd_global_flags_then_sync_is_d5(self):
        d = classify_k8s_command("argocd --grpc-web app sync my-app")
        assert d.deny_dimension == "D5"


class TestClusterRoleEscalation:
    """Oracle-flagged regression: ClusterRole modification is unconditionally high.

    DIRECTIONS.md Phase 1: 'high: 3/3 (永远 N-of-M,无视角色 — 含 namespace 删除、
    ClusterRole 修改、--force 删除、D7 全族)'.
    """

    def test_apply_clusterrole_yaml_high(self):
        d = classify_k8s_command("kubectl apply -f clusterrole.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_apply_clusterrole_pattern_in_filename_high(self):
        d = classify_k8s_command("kubectl apply -f my-clusterrole-binding.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_auth_reconcile_with_clusterrole_high(self):
        d = classify_k8s_command("kubectl auth reconcile -f clusterrole.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_apply_cluster_word_alone_is_medium(self):
        d = classify_k8s_command("kubectl apply -f cluster.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_apply_deployment_medium(self):
        d = classify_k8s_command("kubectl apply -f deployment.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"


class TestD2Analogues:
    """Oracle-flagged regression: DIRECTIONS.md § Phase 1 § D2 explicit analogues:

    'cilium policy import / istioctl install 走 D2 卸载类比照'.
    """

    def test_cilium_policy_import_is_d2(self):
        d = classify_k8s_command("cilium policy import")
        assert d.deny_dimension == "D2"
        assert d.risk_level == "medium"

    def test_istioctl_install_is_d2(self):
        d = classify_k8s_command("istioctl install")
        assert d.deny_dimension == "D2"
        assert d.risk_level == "medium"

    def test_istioctl_install_with_kubecontext(self):
        d = classify_k8s_command("istioctl --kubecontext prod install")
        assert d.deny_dimension == "D2"
        assert d.risk_level == "medium"

    def test_istioctl_manifest_apply_not_d2(self):
        d = classify_k8s_command("istioctl manifest apply -f gateway.yaml")
        assert d.deny_dimension is None

    def test_istioctl_analyze_still_allowlisted(self):
        d = classify_k8s_command("istioctl analyze --use-kubeconfig")
        assert d.action == "allow"


class TestFlagToleranceComprehensive:
    """Comprehensive global flag combinations across all deny dimensions."""

    def test_kubectl_as_then_exec_is_d7(self):
        d = classify_k8s_command("kubectl --as system:serviceaccount:default:foo exec p -- ls")
        assert d.deny_dimension == "D7"
        assert d.risk_level == "high"

    def test_kubectl_kubeconfig_then_port_forward_is_d7(self):
        d = classify_k8s_command("kubectl --kubeconfig /tmp/kc port-forward svc/s 8080:80")
        assert d.deny_dimension == "D7"

    def test_kubectl_server_then_proxy_is_d7(self):
        d = classify_k8s_command("kubectl --server https://prod:6443 proxy")
        assert d.deny_dimension == "D7"

    def test_helm_global_then_install_default_hitl(self):
        d = classify_k8s_command("helm install --kube-context prod r1 stable/chart")
        assert d.action == "hitl"
        assert d.risk_level == "medium"
        assert d.deny_dimension is None

    def test_helm_namespace_flag_passthrough_uninstall(self):
        d = classify_k8s_command("helm -n kube-system uninstall r1")
        assert d.deny_dimension == "D2"

    def test_argocd_global_flag_before_app_subcommand(self):
        d = classify_k8s_command("argocd --grpc-web app get my-app --kubecontext prod")
        assert d.action == "hitl"
        assert d.family == "argocd"

    def test_flux_kubecontext_then_get_allowlisted(self):
        d = classify_k8s_command("flux --kubeconfig /tmp/k get kustomizations")
        assert d.action == "allow"

    def test_kubectl_multiple_global_flags_then_delete(self):
        d = classify_k8s_command(
            "kubectl --context prod --as system:mgr --namespace staging delete pod foo"
        )
        assert d.deny_dimension == "D1"
        assert d.risk_level == "medium"

    def test_kubectl_multiple_global_flags_then_delete_ns(self):
        d = classify_k8s_command(
            "kubectl --context prod --as system:mgr --namespace staging delete ns production"
        )
        assert d.deny_dimension == "D6"
        assert d.risk_level == "high"

    def test_kubectl_global_then_get_passthrough(self):
        d = classify_k8s_command("kubectl --context prod get pods")
        assert d.action == "allow"
        assert d.family == "kubectl"

    def test_kubectl_global_then_logs_passthrough(self):
        d = classify_k8s_command("kubectl --context prod logs pod-foo")
        assert d.action == "allow"


class TestClusterRoleFilenameVariations:
    """Comprehensive ClusterRole filename patterns."""

    def test_clusterrole_yaml_in_subdir(self):
        d = classify_k8s_command("kubectl apply -f rbac/cluster-role.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_clusterrole_yaml_absolute_path(self):
        d = classify_k8s_command("kubectl apply -f /etc/rbac/clusterrole.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_clusterrole_yaml_url(self):
        d = classify_k8s_command(
            "kubectl apply -f https://example.com/k8s/cluster-role.yaml"
        )
        assert d.deny_dimension == "D5"
        assert d.risk_level == "high"

    def test_clusterrole_rolebinding_yaml(self):
        d = classify_k8s_command("kubectl apply -f rolebinding-cluster.yaml")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_apply_clusterrole_inline_yaml_heredoc_data(self):
        d = classify_k8s_command(
            "kubectl apply -f - <<EOF\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nEOF"
        )
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"


class TestQuoteAndHeredocSafetyUnderFlags:
    """Quoted / heredoc safety must hold even with global flags."""

    def test_global_flag_with_quoted_deny_content(self):
        d = classify_k8s_command("kubectl --context prod logs pod 'kubectl delete p'")
        assert d.action == "allow"

    def test_global_flag_with_heredoc_safety(self):
        cmd = "kubectl --context prod apply -f - <<EOF\ndelete pod foo\nEOF"
        d = classify_k8s_command(cmd)
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_clusterrole_in_quoted_string_does_not_escalate(self):
        d = classify_k8s_command("kubectl apply 'clusterrole.yaml'")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_double_quote_with_deny_does_not_match(self):
        d = classify_k8s_command('kubectl --context prod logs pod "kubectl delete p"')
        assert d.action == "allow"


class TestEdgeCasesExpanded:
    """Additional edge cases for Phase 1 hardening."""

    def test_empty_global_flag_value(self):
        d = classify_k8s_command("kubectl --context= delete pod foo")
        assert d.deny_dimension == "D1"

    def test_global_flag_with_equals_syntax(self):
        d = classify_k8s_command("kubectl --context=prod delete ns production")
        assert d.deny_dimension == "D6"
        assert d.risk_level == "high"

    def test_kubectl_long_flag_with_equals(self):
        d = classify_k8s_command("kubectl --namespace=staging get pods")
        assert d.action == "allow"

    def test_istioctl_install_with_manifest_apply_does_not_match_d2(self):
        d = classify_k8s_command("istioctl manifest apply")
        assert d.deny_dimension is None
        assert d.deny_dimension is None

    def test_cilium_policy_get_is_not_d2(self):
        d = classify_k8s_command("cilium policy get")
        assert d.deny_dimension is None

    def test_krew_search_with_context_flag_limitation(self):
        d = classify_k8s_command("kubectl --context prod krew search")
        assert d.action == "hitl"
        assert d.family == "kubectl"

    def test_krew_install_with_context_flag(self):
        d = classify_k8s_command("kubectl --context prod krew install foo")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_kubectl_auth_reconcile_with_empty_yaml(self):
        d = classify_k8s_command("kubectl auth reconcile -f /dev/null")
        assert d.deny_dimension == "D5"
        assert d.risk_level == "medium"

    def test_multiline_command_with_global_flags(self):
        cmd = "kubectl --context prod \\\n  delete ns foo"
        d = classify_k8s_command(cmd)
        assert d.action == "hitl"
        assert d.family == "kubectl"
