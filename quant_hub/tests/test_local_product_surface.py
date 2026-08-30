from __future__ import annotations

import ast
from copy import deepcopy
import inspect
import unittest

from quant_hub.ops.local_product_surface import (
    CANCELLED_MODULE_SURFACES,
    LEGITIMATE_OPERATION_IDENTITIES,
    LocalProductSurfaceError,
    scan_local_product_surface,
    validate_local_product_surface,
)


EXPECTED_FIELDS = {
    "source_tree",
    "installed_wheel_entry_names",
    "console_entrypoints",
    "config_schema_filenames",
    "runbook_filenames",
    "scheduled_task_names",
}


def _fullwidth_ascii(value: str) -> str:
    return "".join(
        chr(ord(character) + 0xFEE0)
        if "!" <= character <= "~"
        else character
        for character in value
    )


def clean_inventory() -> dict[str, object]:
    return {
        "source_tree": [
            {
                "path": "ops/local_deploy.py",
                "source": (
                    "from quant_hub.ops import local_release_identity\n"
                    "OPERATIONS = (\n"
                    "    'c_to_d_final_state_migration',\n"
                    "    'semantic_promotion_checkpoint',\n"
                    "    'mcp_installer_byte_rollback',\n"
                    "    'active_prior_rollback',\n"
                    "    'ds_campaign_replay',\n"
                    ")\n"
                ),
            },
            {
                "path": "ops/writer_handoff.py",
                "source": "def main() -> int:\n    return 0\n",
            },
        ],
        "installed_wheel_entry_names": [
            "quant_hub/ops/local_deploy.py",
            "quant_hub/ops/writer_handoff.py",
            "quant_research_hub-0.1.dist-info/entry_points.txt",
        ],
        "console_entrypoints": [
            {
                "name": "qrh-publish",
                "target": "quant_hub.ops.publish:main",
            },
            {
                "name": "qrh-writer-handoff",
                "target": "quant_hub.ops.writer_handoff:main",
            },
        ],
        "config_schema_filenames": [
            "active_prior_rollback.schema.json",
            "c_to_d_final_state_migration.schema.json",
            "mcp_installer_byte_rollback.schema.json",
            "semantic_promotion_checkpoint.schema.json",
        ],
        "runbook_filenames": [
            "active_prior_rollback.md",
            "bootstrap_first_pair.md",
            "ds_campaign_replay.md",
            "mcp_installer_byte_rollback.md",
            "writer_handoff.md",
        ],
        "scheduled_task_names": [
            r"\QuantResearchHub\DSCampaignReplay",
            r"\QuantResearchHub\SemanticPromotionCheckpoint",
        ],
    }


def validate(inventory: object):  # type: ignore[no-untyped-def]
    return validate_local_product_surface(
        root="src/quant_hub",
        inventory=inventory,
    )


class LocalProductSurfaceTests(unittest.TestCase):
    def test_clean_closed_inventory_allows_specific_local_operations(self) -> None:
        report = validate(clean_inventory())
        self.assertTrue(report.passed)
        self.assertEqual(
            {
                "c_to_d_final_state_migration",
                "semantic_promotion_checkpoint",
                "mcp_installer_byte_rollback",
                "active_prior_rollback",
                "ds_campaign_replay",
            },
            set(LEGITIMATE_OPERATION_IDENTITIES),
        )
        self.assertEqual("src/quant_hub", report.root)
        self.assertEqual(2, report.source_file_count)
        self.assertEqual(3, report.installed_wheel_entry_count)
        self.assertEqual(2, report.console_entrypoint_count)
        self.assertEqual(4, report.config_schema_count)
        self.assertEqual(5, report.runbook_count)
        self.assertEqual(2, report.scheduled_task_count)

    def test_scan_returns_exact_violations_without_discovering_real_tree(self) -> None:
        inventory = clean_inventory()
        frozen = deepcopy(inventory)
        inventory["source_tree"] = [
            {"path": "ops/cold_bundle.py", "source": "VALUE = 1\n"}
        ]
        inventory["console_entrypoints"] = [
            {
                "name": "qrh-restore-cold-bundle",
                "target": "quant_hub.ops.publish:main",
            }
        ]
        report = scan_local_product_surface(
            root="src/quant_hub",
            inventory=inventory,
        )
        self.assertFalse(report.passed)
        self.assertEqual(
            {
                (
                    "console entrypoint",
                    "cancelled_surface",
                    "qrh-restore-cold-bundle",
                ),
                (
                    "source tree",
                    "cancelled_surface",
                    "ops/cold_bundle.py",
                ),
            },
            {
                (item.category, item.code, item.identity)
                for item in report.violations
            },
        )
        with self.assertRaises(LocalProductSurfaceError) as raised:
            validate(inventory)
        self.assertEqual(report, raised.exception.report)
        self.assertEqual(
            frozen["installed_wheel_entry_names"],
            inventory["installed_wheel_entry_names"],
        )

        parameters = inspect.signature(scan_local_product_surface).parameters
        self.assertEqual({"root", "inventory"}, set(parameters))
        self.assertTrue(
            all(
                parameter.kind is inspect.Parameter.KEYWORD_ONLY
                and parameter.default is inspect.Parameter.empty
                for parameter in parameters.values()
            )
        )

    def test_inventory_and_records_are_closed(self) -> None:
        for mutation in ("extra", "missing", "bad_source", "bad_entrypoint"):
            with self.subTest(mutation=mutation):
                inventory = clean_inventory()
                if mutation == "extra":
                    inventory["recovery"] = []
                elif mutation == "missing":
                    inventory.pop("runbook_filenames")
                elif mutation == "bad_source":
                    inventory["source_tree"][0]["encoding"] = "utf-8"
                else:
                    inventory["console_entrypoints"][0]["group"] = "console_scripts"
                with self.assertRaisesRegex(LocalProductSurfaceError, "closed"):
                    validate(inventory)
        self.assertEqual(EXPECTED_FIELDS, set(clean_inventory()))

    def test_source_tree_rejects_every_cancelled_module_surface(self) -> None:
        self.assertEqual(
            {
                "cold_bundle",
                "cold_restore",
                "recovery_bundle",
                "failure_domain",
                "state_only_backup",
                "publish_recovery",
                "operational_source",
                "production_host_facts",
                "writer_handoff_client",
                "restore_cold_bundle",
                "checkpoint_cli",
            },
            set(CANCELLED_MODULE_SURFACES),
        )
        for surface in CANCELLED_MODULE_SURFACES:
            with self.subTest(surface=surface):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": f"ops/{surface}.py", "source": "VALUE = 1\n"}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "source tree.*cancelled"
                ):
                    validate(inventory)

    def test_ast_rejects_cancelled_imports_and_dynamic_capability_presence(self) -> None:
        sources = (
            "import quant_hub.ops.cold_bundle\n",
            "import quant_hub.ops.production_host_facts_cli\n",
            "from quant_hub.ops import cold_restore\n",
            "from .recovery_bundle import build\n",
            (
                "import importlib as loader\n"
                "loader.import_module('quant_hub.ops.failure_domain')\n"
            ),
            (
                "from importlib import import_module as load\n"
                "load('quant_hub.ops.state_' + 'only_backup')\n"
            ),
            "__import__('quant_hub.ops.writer_handoff_client')\n",
            (
                "from importlib.util import find_spec as locate\n"
                "TARGET = 'quant_hub.ops.checkpoint_cli'\n"
                "locate(TARGET)\n"
            ),
            (
                "from importlib import import_module as load\n"
                "A = 'quant_hub.ops.restore_'\n"
                "B = 'cold_'\n"
                "C = 'bundle'\n"
                "TARGET = A + B + C\n"
                "load(TARGET)\n"
            ),
            (
                "import importlib\n"
                "load = importlib.import_module\n"
                "load('quant_hub.ops.operational_source')\n"
            ),
            (
                "import importlib\n"
                "getattr(importlib, 'import_module')"
                "('quant_hub.ops.writer_handoff_client')\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError,
                    "AST.*(cancelled|dynamic_capability_forbidden)",
                ):
                    validate(inventory)

        inventory = clean_inventory()
        inventory["source_tree"] = [
            {
                "path": "ops/local_deploy.py",
                "source": (
                    "from importlib import import_module as load\n"
                    "load(runtime_selected_module)\n"
                ),
            }
        ]
        with self.assertRaisesRegex(
            LocalProductSurfaceError, "dynamic_capability_forbidden"
        ):
            validate(inventory)

    def test_dynamic_import_assignment_and_static_container_chains_are_checked(self) -> None:
        sources = (
            (
                "import importlib\n"
                "loader = importlib\n"
                "loader.import_module('quant_hub.ops.production_host_facts')\n"
            ),
            (
                "from importlib import import_module\n"
                "loaders = (import_module,)\n"
                "loaders[0]('quant_hub.ops.production_host_facts')\n"
            ),
            (
                "from importlib import import_module\n"
                "loaders = [import_module]\n"
                "loaders[0]('quant_hub.ops.production_host_facts')\n"
            ),
            (
                "from importlib import import_module\n"
                "loaders = {'load': import_module}\n"
                "loaders['load']('quant_hub.ops.production_host_facts')\n"
            ),
            (
                "import importlib\n"
                "module_api = importlib\n"
                "module_api_2 = module_api\n"
                "load = module_api_2.import_module\n"
                "load('quant_hub.ops.production_host_facts')\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_dynamic_import_callable_escape_fails_closed(self) -> None:
        sources = (
            (
                "from importlib import import_module\n"
                "loaders = (import_module,)\n"
                "loaders[index]('json')\n"
            ),
            (
                "from importlib import import_module\n"
                "loaders = [import_module]\n"
                "sink(loaders)\n"
            ),
            (
                "from importlib import import_module\n"
                "loaders = {'load': import_module}\n"
                "sink(loaders)\n"
            ),
            (
                "from importlib import import_module\n"
                "holder.loader = import_module\n"
            ),
            (
                "from importlib import import_module\n"
                "holder['loader'] = import_module\n"
            ),
            (
                "from importlib import import_module\n"
                "sink(import_module)\n"
            ),
            (
                "from importlib import import_module\n"
                "def expose():\n"
                "    return import_module\n"
            ),
            (
                "from importlib.util import find_spec\n"
                "def expose(loader=find_spec):\n"
                "    return loader\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError,
                    "dynamic_capability_forbidden",
                ):
                    validate(inventory)

    def test_dynamic_capability_is_forbidden_in_every_expression_shape(self) -> None:
        sources = (
            "expose = lambda: import_module\nexpose()('quant_hub.ops.production_host_facts')\n",
            "load = import_module if condition else safe\nload('json')\n",
            "load = condition and import_module\nload('json')\n",
            "importlib.__dict__.get('import_module')('json')\n",
            "vars(importlib).get('import_module')('json')\n",
            "importlib.__getattribute__('import_module')('json')\n",
            "(import_module,)[index]('json')\n",
            "loaders = [item for item in (import_module,)]\n",
            "for load in (import_module,):\n    load('json')\n",
            "(exec,)[index]('value = 1')\n",
            "(exec if condition else safe)('value = 1')\n",
            "run = exec\nrun = run\nrun('value = 1')\n",
            "module = import_module('json')\n",
            "find_spec('json')\n",
            "compile('value = 1', '<gate>', 'exec')\n",
            "eval('1 + 1')\n",
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_static_capability_identifiers_are_forbidden_in_all_ast_positions(self) -> None:
        sources = (
            "import import_module\n",
            "import find_spec\n",
            "import eval\n",
            "import __loader__\n",
            "import load_module as safe\n",
            "import harmless.import_module\n",
            "import harmless as importlib\n",
            "import harmless as __loader__\n",
            "from harmless.import_module import safe\n",
            "from harmless import import_module as locate\n",
            "from harmless import find_spec\n",
            "from harmless import __loader__\n",
            "from harmless import safe as import_module\n",
            "from harmless import safe as eval\n",
            "from harmless import safe as __loader__\n",
            "adapter.import_module('json')\n",
            "adapter.find_spec('json')\n",
            "adapter.eval('1')\n",
            "adapter.exec('value = 1')\n",
            "adapter.load_module('json')\n",
            "value = __loader__\n",
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_static_mapping_and_getattr_capability_lookups_are_forbidden(self) -> None:
        sources = (
            "import sys\nsys.modules['im' + 'portlib']\n",
            "import sys as runtime\nruntime.modules['built' + 'ins']\n",
            "import sys as runtime\ngetattr(runtime, 'mo' + 'dules')\n",
            "from sys import modules as registry\n",
            "globals()['__' + 'builtins__']\n",
            "vars()['im' + 'port_module']\n",
            "globals().get('e' + 'val')\n",
            "globals().__getitem__('e' + 'xec')\n",
            "vars().pop('com' + 'pile')\n",
            "globals()[f\"{'e' + 'val'}\"]\n",
            "globals()[f\"{'eval'!s}\"]\n",
            "globals()[f\"{'e' + 'val':}\"]\n",
            "globals()[f\"{'e' + 'val':s}\"]\n",
            "globals()[f\"{'eval'!s:s}\"]\n",
            "globals()[f\"{'eval':{''}}\"]\n",
            "vars().get(f\"find_{'spec'}\")\n",
            "getattr(object(), 'im' + 'port_module')\n",
            "getattr(object(), f\"load_{'module'}\")\n",
            "getattr(sys.modules['json'], runtime_attribute)\n",
            "getattr(globals()['import' + 'lib'], runtime_attribute)\n",
            "getattr(vars().get('built' + 'ins'), runtime_attribute)\n",
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_bounded_sys_module_state_lookups_are_forbidden(self) -> None:
        sources = (
            "import sys\nsys.__dict__['modules']\n",
            "import sys\nsys.__dict__.get('mo' + 'dules')\n",
            "import sys\nvars(sys)['modules']\n",
            "from sys import __dict__ as state\nstate['modules']\n",
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_bounded_namespace_alias_lookups_are_forbidden(self) -> None:
        sources = (
            "namespace = globals()\nnamespace['eval']\n",
            "namespace = vars()\nnamespace.get('import_' + 'module')\n",
            "factory = globals\nfactory()['find_spec']\n",
            "factory = vars\nfactory().get('compile')\n",
            (
                "def inspect_local():\n"
                "    namespace = globals()\n"
                "    return namespace['__builtins__']\n"
            ),
            "namespace = globals()\nnamespace = {}\nnamespace['eval']\n",
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_fixed_point_sys_alias_chains_are_forbidden(self) -> None:
        sources = (
            "import sys\nruntime_2 = runtime\nruntime = sys\nruntime_2.modules\n",
            (
                "import sys\n"
                "runtime_2: object = runtime\n"
                "runtime: object = sys\n"
                "runtime_2.modules\n"
            ),
            "import sys\nmods_2 = mods\nmods = sys.modules\nmods_2.get('json')\n",
            (
                "import sys\n"
                "mods_2 = mods\n"
                "mods = getattr(sys, 'modules')\n"
                "getattr(mods_2['json'], runtime_attribute)\n"
            ),
            "import sys\nstate_2 = state\nstate = sys.__dict__\nstate_2['modules']\n",
            "import sys\nstate_2 = state\nstate = vars(sys)\nstate_2.get('modules')\n",
            (
                "import sys\n"
                "state_2 = state\n"
                "state = getattr(sys, '__dict__')\n"
                "state_2['modules']\n"
            ),
            (
                "from sys import __dict__ as state\n"
                "state_2 = state\n"
                "state_2['modules']\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_fixed_point_namespace_and_factory_alias_chains_are_forbidden(self) -> None:
        sources = (
            "namespace_2 = namespace\nnamespace = globals()\nnamespace_2['eval']\n",
            "namespace_2 = namespace\nnamespace = vars()\nnamespace_2.get('compile')\n",
            "factory_2 = factory\nfactory = globals\nfactory_2()['import_module']\n",
            (
                "factory_2 = factory\n"
                "namespace = factory_2()\n"
                "factory = globals\n"
                "namespace['eval']\n"
            ),
            (
                "def inspect_local():\n"
                "    factory_2 = factory\n"
                "    factory = vars\n"
                "    return factory_2().get('__builtins__')\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_fixed_point_aliases_cover_every_nested_control_block(self) -> None:
        sources = (
            "import sys\nif False:\n    runtime = sys\n    runtime.modules\n",
            (
                "import sys\n"
                "if first:\n"
                "    pass\n"
                "elif second:\n"
                "    runtime: object = sys\n"
                "    runtime.modules\n"
            ),
            (
                "import sys\n"
                "if condition:\n"
                "    pass\n"
                "else:\n"
                "    runtime = sys\n"
                "    runtime.modules\n"
            ),
            (
                "import sys\n"
                "try:\n"
                "    runtime = sys\n"
                "    runtime.modules\n"
                "except Exception:\n"
                "    pass\n"
            ),
            (
                "import sys\n"
                "try:\n"
                "    pass\n"
                "except Exception:\n"
                "    runtime = sys\n"
                "    runtime.modules\n"
            ),
            (
                "import sys\n"
                "try:\n"
                "    pass\n"
                "except Exception:\n"
                "    pass\n"
                "else:\n"
                "    runtime = sys\n"
                "    runtime.modules\n"
            ),
            (
                "import sys\n"
                "try:\n"
                "    pass\n"
                "finally:\n"
                "    runtime = sys\n"
                "    runtime.modules\n"
            ),
            "import sys\nfor item in items:\n    runtime = sys\n    runtime.modules\n",
            (
                "import sys\n"
                "for item in items:\n"
                "    pass\n"
                "else:\n"
                "    runtime = sys\n"
                "    runtime.modules\n"
            ),
            "import sys\nwhile condition:\n    runtime = sys\n    runtime.modules\n",
            (
                "import sys\n"
                "while condition:\n"
                "    pass\n"
                "else:\n"
                "    runtime = sys\n"
                "    runtime.modules\n"
            ),
            (
                "import sys\n"
                "with context():\n"
                "    runtime = sys\n"
                "    runtime.modules\n"
            ),
            (
                "import sys\n"
                "match subject:\n"
                "    case 1:\n"
                "        runtime = sys\n"
                "        runtime.modules\n"
            ),
            "if True:\n    namespace = globals()\n    namespace['eval']\n",
            (
                "try:\n"
                "    factory = vars\n"
                "finally:\n"
                "    factory()['compile']\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_control_block_aliases_close_each_lexical_scope(self) -> None:
        sources = (
            (
                "import sys\n"
                "runtime_3 = runtime_2\n"
                "if condition:\n"
                "    runtime_2 = runtime\n"
                "runtime = sys\n"
                "runtime_3.modules\n"
            ),
            (
                "import sys\n"
                "def inspect_runtime():\n"
                "    runtime_3 = runtime_2\n"
                "    if condition:\n"
                "        runtime_2 = runtime\n"
                "    runtime = sys\n"
                "    runtime = object()\n"
                "    return runtime_3.modules\n"
            ),
            (
                "import sys\n"
                "async def inspect_runtime():\n"
                "    runtime_2: object = runtime\n"
                "    while condition:\n"
                "        runtime: object = sys\n"
                "    return runtime_2.modules\n"
            ),
            (
                "import sys\n"
                "class RuntimeProbe:\n"
                "    runtime_3 = runtime_2\n"
                "    match subject:\n"
                "        case 1:\n"
                "            runtime_2 = runtime\n"
                "    runtime = sys\n"
                "    runtime = object()\n"
                "    modules = runtime_3.modules\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_parent_aliases_flow_into_nested_scopes_and_declarations(self) -> None:
        sources = [
            (
                "import sys as runtime\n"
                "def inspect_runtime():\n"
                "    return runtime.modules\n"
            ),
            (
                "import sys as runtime\n"
                "async def inspect_runtime():\n"
                "    return runtime.modules\n"
            ),
            (
                "import sys as runtime\n"
                "class RuntimeProbe:\n"
                "    modules = runtime.modules\n"
            ),
            "import sys as runtime\ninspect_runtime = lambda: runtime.modules\n",
            (
                "import sys\n"
                "def outer():\n"
                "    runtime = sys\n"
                "    def inner():\n"
                "        return runtime.modules\n"
            ),
            (
                "import sys\n"
                "def outer():\n"
                "    runtime = sys\n"
                "    async def inner():\n"
                "        return runtime.modules\n"
            ),
            (
                "import sys\n"
                "def outer():\n"
                "    runtime = sys\n"
                "    class Inner:\n"
                "        modules = runtime.modules\n"
            ),
            (
                "import sys\n"
                "def outer():\n"
                "    runtime = sys\n"
                "    inspect_runtime = lambda: runtime.modules\n"
            ),
            (
                "namespace = globals()\n"
                "def inspect_runtime():\n"
                "    return namespace['eval']\n"
            ),
            (
                "factory = vars\n"
                "def inspect_runtime():\n"
                "    return factory()['compile']\n"
            ),
            (
                "import sys\n"
                "state = sys.__dict__\n"
                "def inspect_runtime():\n"
                "    return state['modules']\n"
            ),
            (
                "import sys\n"
                "runtime_2 = runtime\n"
                "runtime = sys\n"
                "def inspect_runtime():\n"
                "    return runtime_2.modules\n"
            ),
            (
                "import sys\n"
                "if condition:\n"
                "    runtime = sys\n"
                "def inspect_runtime():\n"
                "    return runtime.modules\n"
            ),
            "import sys as runtime\ndef inspect(value=runtime.modules):\n    pass\n",
            "import sys as runtime\ndef inspect(*, value=runtime.modules):\n    pass\n",
            (
                "import sys\n"
                "def outer():\n"
                "    runtime = sys\n"
                "    def inner(value=runtime.modules):\n"
                "        pass\n"
            ),
            "import sys as runtime\ninspect = lambda value=runtime.modules: value\n",
            (
                "import sys as runtime\n"
                "@runtime.modules['builtins'].staticmethod\n"
                "def inspect():\n"
                "    pass\n"
            ),
            (
                "import sys as runtime\n"
                "@runtime.modules['builtins'].staticmethod\n"
                "class RuntimeProbe:\n"
                "    pass\n"
            ),
            (
                "import sys as runtime\n"
                "class RuntimeProbe(runtime.modules['builtins'].object):\n"
                "    pass\n"
            ),
            (
                "import sys as runtime\n"
                "class RuntimeProbe(metaclass=runtime.modules['builtins'].type):\n"
                "    pass\n"
            ),
            (
                "import sys as runtime\n"
                "def inspect(value: runtime.modules) -> runtime.modules:\n"
                "    pass\n"
            ),
            (
                "import sys as runtime\n"
                "async def inspect(value=runtime.modules) -> runtime.modules:\n"
                "    pass\n"
            ),
        ]
        if "type_params" in ast.FunctionDef._fields:
            sources.extend(
                (
                    "import sys as runtime\ndef inspect[T: runtime.modules]():\n    pass\n",
                    "import sys as runtime\nclass Inspect[T: runtime.modules]:\n    pass\n",
                )
            )

        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_class_scope_has_python_non_closure_boundary(self) -> None:
        inventory = clean_inventory()
        inventory["source_tree"] = [
            {
                "path": "ops/local_deploy.py",
                "source": (
                    "import sys\n"
                    "class Outer:\n"
                    "    class_runtime = sys\n"
                    "    def method():\n"
                    "        return class_runtime.modules\n"
                    "    async def async_method():\n"
                    "        return class_runtime.modules\n"
                    "    class Nested:\n"
                    "        modules = class_runtime.modules\n"
                    "    inspect = lambda: class_runtime.modules\n"
                    "safe_outer_value = class_runtime.modules\n"
                ),
            }
        ]
        self.assertTrue(validate(inventory).passed)

    def test_enclosing_aliases_cross_class_but_class_locals_do_not(self) -> None:
        cancelled_sources = (
            (
                "import sys\n"
                "def outer():\n"
                "    runtime = sys\n"
                "    class RuntimeProbe:\n"
                "        def method():\n"
                "            return runtime.modules\n"
            ),
            (
                "import sys\n"
                "def outer():\n"
                "    runtime = sys\n"
                "    class RuntimeProbe:\n"
                "        class Nested:\n"
                "            modules = runtime.modules\n"
            ),
            (
                "import sys\n"
                "def outer():\n"
                "    runtime = sys\n"
                "    class RuntimeProbe:\n"
                "        inspect = lambda: runtime.modules\n"
            ),
        )
        for source in cancelled_sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_class_local_aliases_apply_to_declaration_time_expressions(self) -> None:
        sources = (
            (
                "import sys\n"
                "class RuntimeProbe:\n"
                "    runtime = sys\n"
                "    @runtime.modules['builtins'].staticmethod\n"
                "    def inspect():\n"
                "        pass\n"
            ),
            (
                "import sys\n"
                "class RuntimeProbe:\n"
                "    runtime = sys\n"
                "    def inspect(value=runtime.modules):\n"
                "        pass\n"
            ),
            (
                "import sys\n"
                "class RuntimeProbe:\n"
                "    runtime = sys\n"
                "    inspect = lambda value=runtime.modules: value\n"
            ),
            (
                "import sys\n"
                "class RuntimeProbe:\n"
                "    runtime = sys\n"
                "    class Nested(runtime.modules['builtins'].object):\n"
                "        pass\n"
            ),
            (
                "import sys\n"
                "class RuntimeProbe:\n"
                "    runtime = sys\n"
                "    class Nested(metaclass=runtime.modules['builtins'].type):\n"
                "        pass\n"
            ),
        )
        for source in sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_nested_bindings_and_benign_declarations_do_not_pollute_outer(self) -> None:
        inventory = clean_inventory()
        inventory["source_tree"] = [
            {
                "path": "ops/local_deploy.py",
                "source": (
                    "import re\n"
                    "def bind_nested():\n"
                    "    import sys as nested_runtime\n"
                    "    return nested_runtime.version\n"
                    "class BindClassLocal:\n"
                    "    import sys as class_runtime\n"
                    "    def method():\n"
                    "        return class_runtime.modules\n"
                    "def benign_default(value=re.compile('safe')):\n"
                    "    return value\n"
                    "def benign_annotations(value: ordinary.modules) -> ordinary.modules:\n"
                    "    return value\n"
                    "@ordinary.decorator\n"
                    "def benign_decorator():\n"
                    "    pass\n"
                    "class BenignClass(ordinary.Base, metaclass=ordinary.Meta):\n"
                    "    pass\n"
                    "benign_lambda = lambda value=ReferenceCompiler().compile(): value\n"
                    "def benign_named_expression(value=(runtime := object())):\n"
                    "    return runtime.modules\n"
                    "safe_nested_value = nested_runtime.modules\n"
                    "safe_class_value = class_runtime.modules\n"
                ),
            }
        ]
        self.assertTrue(validate(inventory).passed)

    def test_nested_scope_assignments_do_not_pollute_the_outer_scope(self) -> None:
        inventory = clean_inventory()
        inventory["source_tree"] = [
            {
                "path": "ops/local_deploy.py",
                "source": (
                    "import sys\n"
                    "def bind_in_function():\n"
                    "    if condition:\n"
                    "        function_runtime = sys\n"
                    "async def bind_in_async_function():\n"
                    "    async_runtime = sys\n"
                    "class BindInClass:\n"
                    "    class_runtime = sys\n"
                    "def outer_function():\n"
                    "    class NestedClass:\n"
                    "        nested_class_runtime = sys\n"
                    "    return nested_class_runtime.modules\n"
                    "class OuterClass:\n"
                    "    def nested_method():\n"
                    "        method_runtime = sys\n"
                    "    safe_method_value = method_runtime.modules\n"
                    "safe_function_value = function_runtime.modules\n"
                    "safe_async_value = async_runtime.modules\n"
                    "safe_class_value = class_runtime.modules\n"
                    "safe_lambda_value = (lambda: sys)\n"
                ),
            }
        ]
        self.assertTrue(validate(inventory).passed)

    def test_benign_getattr_and_nonfolded_lookup_boundaries_are_allowed(self) -> None:
        inventory = clean_inventory()
        inventory["source_tree"] = [
            {
                "path": "ops/local_deploy.py",
                "source": (
                    "import sys\n"
                    "import re\n"
                    "import sys as runtime_sys\n"
                    "import import_module_adapter\n"
                    "import harmless.compiler_adapter\n"
                    "from harmless.import_module_adapter import safe\n"
                    "import harmless as compiler_adapter\n"
                    "from harmless import safe as import_module_adapter\n"
                    "from sys import __dict__ as sys_state\n"
                    "KEY = 'eval'\n"
                    "safe_version = sys.version\n"
                    "safe_state = sys.__dict__['version']\n"
                    "safe_state_2 = sys.__dict__.get('version')\n"
                    "safe_state_3 = vars(sys)['version']\n"
                    "safe_state_4 = sys_state['version']\n"
                    "safe_global = globals()['safe_object']\n"
                    "safe_local = vars().get('safe_object')\n"
                    "dynamic_name = globals()[KEY]\n"
                    "dynamic_fstring_name = globals()[f'{KEY}']\n"
                    "dynamic_formatted_name = globals()[f'{KEY:s}']\n"
                    "changed_formatted_name = globals()[f'{KEY:>10}']\n"
                    "namespace = globals()\n"
                    "namespace_2 = namespace\n"
                    "safe_alias_value = namespace['safe_object']\n"
                    "safe_alias_value_2 = namespace_2['safe_object']\n"
                    "factory = vars\n"
                    "factory_2 = factory\n"
                    "safe_factory_value = factory().get('safe_object')\n"
                    "safe_factory_value_2 = factory_2().get('safe_object')\n"
                    "runtime_alias = sys\n"
                    "runtime_alias_2 = runtime_alias\n"
                    "safe_runtime_version = runtime_alias_2.version\n"
                    "state_alias = sys.__dict__\n"
                    "state_alias_2 = state_alias\n"
                    "safe_state_alias = state_alias_2['version']\n"
                    "safe_attribute = getattr(object(), 'safe_attribute')\n"
                    "compiled_regex = regex_api.compile('safe')\n"
                    "compiled_regex_2 = re.compile('safe')\n"
                    "compiled_reference = ReferenceCompiler().compile()\n"
                    "ordinary_compile = getattr(object(), 'compile')\n"
                    "dynamic_safe_attribute = getattr(safe_global, runtime_attribute)\n"
                    "compiler_result = object().compile_result\n"
                ),
            }
        ]
        self.assertTrue(validate(inventory).passed)

    def test_reflective_and_static_dynamic_code_capabilities_are_forbidden(self) -> None:
        cancelled_sources = (
            (
                "import importlib\n"
                "NAME = 'import_' + 'module'\n"
                "getattr(importlib, NAME)"
                "('quant_hub.ops.production_host_facts')\n"
            ),
            (
                "import importlib\n"
                "importlib.__dict__['import_module']"
                "('quant_hub.ops.production_host_facts')\n"
            ),
            (
                "import importlib\n"
                "vars(importlib)['import_module']"
                "('quant_hub.ops.production_host_facts')\n"
            ),
            "exec(\"import quant_hub.ops.production_host_facts\")\n",
            (
                "eval(\"__import__('quant_hub.ops.production_host_facts')\")\n"
            ),
            (
                "compile(\"from quant_hub.ops import production_host_facts\", "
                "'<gate>', 'exec')\n"
            ),
        )
        for source in cancelled_sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

        unverifiable_sources = (
            "import importlib\ngetattr(importlib, runtime_name)\n",
            (
                "import importlib\n"
                "getattr(importlib, 'import_' + runtime_suffix)\n"
            ),
            "import importlib\nimportlib.__dict__[runtime_name]\n",
            "import importlib\nvars(importlib)[runtime_name]\n",
            "exec(runtime_source)\n",
        )
        for source in unverifiable_sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaises(LocalProductSurfaceError):
                    validate(inventory)

    def test_exact_importlib_resources_whitelist_and_static_imports_are_allowed(self) -> None:
        inventory = clean_inventory()
        inventory["source_tree"] = [
            {
                "path": "ops/local_deploy.py",
                "source": (
                    "import json\n"
                    "from pathlib import Path\n"
                    "from importlib.resources import as_file, files as resource_files\n"
                    "PACKAGE_ROOT = resource_files('quant_hub')\n"
                    "def read_resource(name: str) -> str:\n"
                    "    return PACKAGE_ROOT.joinpath(name).read_text()\n"
                ),
            }
        ]
        self.assertTrue(validate(inventory).passed)

    def test_importlib_resources_whitelist_is_exact_and_does_not_bind_base(self) -> None:
        forbidden_sources = (
            "import importlib\n",
            "import ImportLib\n",
            f"import {_fullwidth_ascii('importlib')}\n",
            "import importlib.resources\n",
            "from importlib import resources\n",
            "from ImportLib.resources import files\n",
            "from importlib.resources import *\n",
            "from importlib.resources import read_text\n",
            "from importlib.resources import files as importlib\n",
            "from importlib.resources import files as exec\n",
            "import __builtins__\n",
            "from __builtins__ import len\n",
        )
        for source in forbidden_sources:
            with self.subTest(source=source):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": "ops/local_deploy.py", "source": source}
                ]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "dynamic_capability_forbidden"
                ):
                    validate(inventory)

    def test_cancelled_suffix_variants_remain_token_bound(self) -> None:
        variants = (
            (
                "ops/production_host_facts_cli.py",
                "VALUE = 1\n",
                "production_host_facts",
            ),
            (
                "ops/local_deploy.py",
                "import quant_hub.ops.failure_domain_rotation\n",
                "failure_domain",
            ),
            (
                "ops/local_deploy.py",
                "from quant_hub.ops.failure_domain_authority import require\n",
                "failure_domain",
            ),
        )
        for path, source, expected in variants:
            with self.subTest(path=path, expected=expected):
                inventory = clean_inventory()
                inventory["source_tree"] = [{"path": path, "source": source}]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, expected
                ):
                    validate(inventory)

        inventory = clean_inventory()
        inventory["console_entrypoints"] = [
            {
                "name": "qrh-production-host-facts",
                "target": "quant_hub.ops.production_host_facts_cli:main",
            }
        ]
        with self.assertRaisesRegex(
            LocalProductSurfaceError, "production_host_facts"
        ):
            validate(inventory)

    def test_cancelled_signatures_reject_adjacent_mixed_tokens_only(self) -> None:
        cancelled_paths = (
            ("ops/productionhost_facts.py", "production_host_facts"),
            ("ops/production_hostfacts.py", "production_host_facts"),
            ("ops/failuredomain_authority.py", "failure_domain"),
            ("ops/stateonly_backup.py", "state_only_backup"),
        )
        for path, expected in cancelled_paths:
            with self.subTest(path=path):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": path, "source": "VALUE = 1\n"}
                ]
                with self.assertRaisesRegex(LocalProductSurfaceError, expected):
                    validate(inventory)

        unrelated_paths = (
            "ops/productionhost_factual.py",
            "ops/preproductionhost_facts.py",
            "ops/production_hosting_facts.py",
            "ops/failuredomains_authority.py",
            "ops/failure_model_domain.py",
            "ops/stateonly_backups.py",
            "ops/state_onlyback_pressure.py",
        )
        for path in unrelated_paths:
            with self.subTest(path=path):
                inventory = clean_inventory()
                inventory["source_tree"] = [
                    {"path": path, "source": "VALUE = 1\n"}
                ]
                self.assertTrue(validate(inventory).passed)

    def test_source_paths_reject_case_nfkc_and_path_aliases(self) -> None:
        for path in (
            "ops/COLD_BUNDLE.py",
            f"ops/{_fullwidth_ascii('cold_bundle')}.py",
            "ops/../ops/cold_bundle.py",
            r"ops\cold_bundle.py",
        ):
            with self.subTest(path=path):
                inventory = clean_inventory()
                inventory["source_tree"] = [{"path": path, "source": "VALUE = 1\n"}]
                with self.assertRaises(LocalProductSurfaceError):
                    validate(inventory)

        inventory = clean_inventory()
        inventory["source_tree"] = [
            {"path": "ops/local_deploy.py", "source": "VALUE = 1\n"},
            {"path": "ops/LOCAL_DEPLOY.py", "source": "VALUE = 2\n"},
        ]
        with self.assertRaisesRegex(LocalProductSurfaceError, "path identity"):
            validate(inventory)

    def test_installed_wheel_entries_reject_cancelled_and_alias_names(self) -> None:
        for name in (
            "quant_hub/ops/recovery_bundle.py",
            "quant_hub/ops/FAILURE_DOMAIN_AUTHORITY.py",
            f"quant_hub/ops/{_fullwidth_ascii('state_only_backup')}.py",
            "quant_hub/ops/../ops/cold_restore.py",
        ):
            with self.subTest(name=name):
                inventory = clean_inventory()
                inventory["installed_wheel_entry_names"] = [name]
                with self.assertRaises(LocalProductSurfaceError):
                    validate(inventory)

    def test_console_entrypoint_name_and_target_are_both_closed(self) -> None:
        entries = (
            {
                "name": "qrh-cold-bundle",
                "target": "quant_hub.ops.publish:main",
            },
            {
                "name": "qrh-publish",
                "target": "quant_hub.ops.publish_recovery_cli:main",
            },
            {
                "name": "QRH-RESTORE-COLD-BUNDLE",
                "target": "quant_hub.ops.publish:main",
            },
            {
                "name": _fullwidth_ascii("qrh-failure-domain"),
                "target": "quant_hub.ops.publish:main",
            },
        )
        for entry in entries:
            with self.subTest(entry=entry):
                inventory = clean_inventory()
                inventory["console_entrypoints"] = [entry]
                with self.assertRaises(LocalProductSurfaceError):
                    validate(inventory)

    def test_old_recovery_config_schema_filenames_are_rejected_exactly(self) -> None:
        for name in (
            "recovery.schema.json",
            "recovery_manifest.schema.json",
            "qrh-recovery-protection-receipt-v1.schema.json",
            "checkpoint_manifest.schema.json",
            "state_only_task_authority.schema.json",
            "failure_domain_host_facts.schema.json",
        ):
            with self.subTest(name=name):
                inventory = clean_inventory()
                inventory["config_schema_filenames"] = [name]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "config schema.*cancelled"
                ):
                    validate(inventory)

    def test_old_recovery_runbook_filenames_are_rejected_exactly(self) -> None:
        for name in (
            "recovery.md",
            "cold_recovery.md",
            "state_only_backup.md",
            "restore_cold_bundle.md",
            "cross_host_recovery.md",
        ):
            with self.subTest(name=name):
                inventory = clean_inventory()
                inventory["runbook_filenames"] = [name]
                with self.assertRaisesRegex(
                    LocalProductSurfaceError, "runbook.*cancelled"
                ):
                    validate(inventory)

    def test_old_scheduled_tasks_and_task_path_aliases_are_rejected(self) -> None:
        for name in (
            r"\QuantResearchHub\StateOnlyBackup",
            r"\QUANTRESEARCHHUB\RECOVERYPROTECTION",
            "\\QuantResearchHub\\" + _fullwidth_ascii("cold_recovery"),
            r"\QuantResearchHub\..\StateOnlyBackup",
        ):
            with self.subTest(name=name):
                inventory = clean_inventory()
                inventory["scheduled_task_names"] = [name]
                with self.assertRaises(LocalProductSurfaceError):
                    validate(inventory)

    def test_root_and_all_inventory_names_reject_normalized_collisions(self) -> None:
        with self.assertRaisesRegex(LocalProductSurfaceError, "root.*alias"):
            validate_local_product_surface(
                root=f"src/{_fullwidth_ascii('quant_hub')}",
                inventory=clean_inventory(),
            )

        inventory = clean_inventory()
        inventory["console_entrypoints"] = [
            {"name": "qrh-publish", "target": "quant_hub.ops.publish:main"},
            {"name": "QRH-PUBLISH", "target": "quant_hub.ops.publish:main"},
        ]
        with self.assertRaisesRegex(LocalProductSurfaceError, "name identity"):
            validate(inventory)

        inventory = deepcopy(clean_inventory())
        inventory["runbook_filenames"] = [
            "local_prior_rollback.md",
            "LOCAL_PRIOR_ROLLBACK.md",
        ]
        with self.assertRaisesRegex(LocalProductSurfaceError, "path identity"):
            validate(inventory)


if __name__ == "__main__":
    unittest.main()
