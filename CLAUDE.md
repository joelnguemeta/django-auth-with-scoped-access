# auth-with-scoped-access

> Mémoire de projet pour agents IA et contributeurs. Lis ce fichier en entier avant de toucher au code : toutes les décisions d'architecture ci-dessous ont été débattues et **actées** — ne les re-litige pas sans demande explicite du propriétaire du projet.

## Vision

Package Django installable **open-source** (ergonomie type `djangorestframework-simplejwt`) qui fournit un système d'autorisation complet : **RBAC** (rôles → permissions) + **ABAC par scope hiérarchique** (périmètre géographique/organisationnel configurable) + **step-up authentication** (ré-authentification pour actions sensibles).

Nom de travail : `django-scoped-access` (nom définitif non arrêté). Une implémentation **Spring Boot** est prévue à terme → le projet est en réalité **une spécification avec deux implémentations** (comme JWT). D'où la règle : la source de vérité est `SPEC.md` (langage-agnostique) + une suite de cas de test partagée en fixtures JSON que toute implémentation doit passer.

## Origine et cas de référence

Le système est extrait et généralisé depuis deux projets réels (chemins locaux sur la machine du propriétaire, hors repo) :

1. **DME** — `/Users/pc/Code/Projets/job/PSE/dme_systems_api`, app `dem_systems_api/users/`.
   Dossier médical électronique. Hiérarchie de scope **profondeur 6** : `NATIONAL → REGIONAL → DISTRICT → HEALTH_AREA → FACILITY → DEPARTMENT`, tenant = FACILITY. Contient déjà : rôles système vs custom par facility, `UserScopeAssignment` (FK par niveau, à généraliser), `covers()` inclusif, `ScopeMixin` de filtrage de querysets, `ReAuthService` (token cache TTL 5 min à usage unique, header `X-ReAuth-Token`).
2. **APSR / SafeRoad** — `/Users/pc/Code/Projets/job/PSE/apsr_api`, app `apsr_api/users/`.
   Hiérarchie **profondeur 1** : `[ORGANIZATION]`, rôles fixes seedés. A déjà le cycle de vie (`granted_by`, `expires_at`, `is_active`, `revoke()`) et un `AuditLog` immuable. Contient aussi l'**anti-pattern à ne jamais reproduire** (voir Doctrine).

Le package doit faire tourner ces deux extrêmes avec la même API. DME sera le premier consommateur ; ses tests existants servent de suite d'intégration de référence.

## Concepts et vocabulaire (à respecter dans le code et la spec)

- **Hierarchy** : liste ordonnée de *levels* (index bas = niveau haut). Profondeur 0..N. Déclarée en config, jamais dans le schéma.
- **Scope / node** : une entité hôte jouant le rôle d'un level (ex. une Facility précise).
- **Assignment** : `user + role + scope` — un rôle ne vaut que dans un périmètre. Couverture **inclusive** : un scope couvre tout son sous-arbre.
- **Anchor** : accesseur déclaré par ressource qui rattache un modèle métier à la hiérarchie (ex. `Diagnosis → "encounter__facility"`).
- **Owner d'un rôle** : nœud propriétaire (null = rôle système global). Le "tenant" n'est PAS un concept du schéma — c'est un level promu via la config.
- **ReAuth (step-up)** : preuve d'identité récente exigée en plus des permissions pour les actions sensibles.

## Décisions d'architecture ACTÉES

1. **Hiérarchie = configuration, pas schéma.** Setting dict style SIMPLE_JWT :
   ```python
   SCOPED_ACCESS = {
       "HIERARCHY": [
           {"level": "NATIONAL"},
           {"level": "REGIONAL", "model": "geography.Region"},
           {"level": "FACILITY", "model": "organization.Facility", "parent": "health_area"},
           # ...
       ],
       "ROLE_OWNER_LEVELS": ["FACILITY"],      # levels autorisés à posséder des rôles custom
       "GRANTABLE_PERMISSIONS": "self",         # anti-escalade (voir §5)
       "REAUTH": {"ENABLED": True, "TTL": 300},
   }
   ```
   `HIERARCHY: []` = RBAC pur sans multi-tenancy (dégradation propre obligatoire).
2. **Un seul arbre de scope en v1.** Validé sur DME (6 niveaux) et APSR (1 niveau). Pas de multi-dimensions, pas de DAG. Assumé et documenté.
3. **`ScopeAssignment` et `Role.owner` utilisent des GenericForeignKey** (`content_type + object_id`), jamais de FK par niveau : c'est ce qui rend le package installable sans que ses migrations dépendent des modèles hôtes.
4. **Ressources rattachées via un registre déclaratif** (autodiscovery type `admin.py`) : `registry.register(Patient, anchor="department")`. Modèle non enregistré = référentiel global = accessible à tout utilisateur authentifié.
5. **Anti-escalade de privilèges (dans le cœur dès la v1)** : un admin délégué ne peut mettre dans un rôle que des permissions qu'il détient lui-même dans ce périmètre (`GRANTABLE_PERMISSIONS: "self"`, surchargeable). Sans ça, l'isolation tenant est percée par le haut.
6. **Règles rôles/tenant** : rôle visible si `owner=None` ou owner couvert par le demandeur ; rôle custom assignable uniquement dans le sous-arbre de son owner ; unicité `(name, owner)` ; gestion déléguée à qui détient `manage_roles` sur un scope couvrant l'owner.
7. **Cycle de vie des assignations** : `valid_from`/`valid_until` (évalués **à la lecture**, jamais par cron), états `ACTIVE → SUSPENDED → REVOKED`, **jamais de hard-delete** (la table est sa propre piste d'audit : `granted_by`, `revoked_by`, `reason`).
8. **Audit par signaux Django** (`assignment_granted`, `assignment_revoked`, `assignment_suspended`, `role_permissions_changed`) : le package émet, l'hôte enregistre. Pas de système d'audit imposé.
9. **Permissions Django natives** (`django.contrib.auth.Permission`) en v1 — pas de catalogue maison.
10. **Permission backend** (`AUTHENTICATION_BACKENDS`) plutôt que surcharge de `User.has_perm` : fonctionne partout, y compris l'admin Django, sans imposer de modèle User.
11. **ReAuth = module optionnel** (extra pip `[reauth]`) avec *verifiers* pluggables : password en v1, PIN/TOTP/WebAuthn ensuite. Token en cache, TTL court, usage unique, invalidation en masse par user.
12. **Contrat frontend** : endpoint standard `GET /me/access/` (permissions effectives + périmètres + rôles). Les claims JWT restent **non autoritatifs** (affichage seulement).
13. **Cache des assignations par requête uniquement** en v1 : garantit la révocation immédiate malgré des access tokens longs. Un cache cross-requêtes devra s'invalider via les signaux du §8.
14. **Postgres-first** ; optimisations futures possibles (`ltree`, Row-Level Security) sans casser le design. Les autres DB : best-effort.
15. **Modèles swappables** (`Role`, `ScopeAssignment`) à la manière de `AUTH_USER_MODEL`.

## Doctrine (règles non négociables)

- **Les vues vérifient des PERMISSIONS, jamais des rôles.** Un rôle n'est qu'un paquet de permissions. L'anti-pattern à bannir est visible dans APSR `users/interfaces/permissions.py` : des classes `IsEditor`/`IsModerator` testent des codes de rôle en dur pendant que la M2M permissions n'est jamais lue → chaque nouveau rôle oblige à modifier le code. Un `HasRole` d'échappement existera mais sera documenté "à éviter".
- **Jamais de hard-delete d'une assignation** — on révoque.
- **L'expiration s'évalue à la lecture**, pas par tâche planifiée.
- **Le moteur (`engine.py`) ne dépend pas de DRF** — la glue DRF est un module à part (extra `[drf]`).
- Toute règle d'autorisation doit exister dans `SPEC.md` + fixtures de test AVANT d'être codée (contrainte double implémentation Python/Java).

## Structure cible du package

```
scoped_access/
├── conf.py            # lecture SCOPED_ACCESS + defaults
├── checks.py          # django checks : config cohérente, accesseurs valides
├── registry.py        # levels + ressources (anchors)
├── models.py          # Role, RolePermission, ScopeAssignment (swappables)
├── backends.py        # ScopedPermissionBackend
├── engine.py          # chain / covers / Q-builders — zéro dépendance DRF
├── signals.py
├── drf/               # extra [drf] : permissions, ScopeQuerySetMixin, /me/access/
└── reauth/            # extra [reauth] : service, verifiers, RequireReAuth, ReAuthView
```

Algorithmes du moteur = généralisation directe de DME `users/utils/scopes.py` : `get_scope_chain` (remontée par anchors/parents déclarés), `covers` (comparaison inclusive par rang), `build_scope_filter` (traduction assignation → `Q()` ORM par concaténation des accesseurs parents).

## État d'avancement & prochaines étapes

- ✅ Architecture complète débattue et actée (juillet 2026) — ce fichier en est le compte rendu.
- ✅ `SPEC.md` v0.1.0-draft rédigée (concepts, règles normatives §4–§8, ReAuth, `/me/access/`, format des cas de conformité).
- ✅ Premiers cas de conformité : `conformance/cases/{coverage,lifecycle,tenancy,flat-rbac}.json` (+ `conformance/README.md` — contrat de l'adapter). Manquent encore : write guard, unicité §8.3, flow ReAuth, payload `/me/access/`.
- ✅ SPEC relue et **validée par le propriétaire** (4 juillet 2026), y compris les micro-décisions : inactif testé avant superuser, pas d'implication entre permissions, superusers non exemptés du ReAuth, anchor null = deny, write guard normatif, cas de conformité append-only.
- ✅ Package `scoped_access` : conf/registry/checks/signals, modèles (Role avec owner GFK, ScopeAssignment avec lifecycle), `engine.py` (covers, has_perm, accessible_nodes, scope_filter_q, R1/R2/R5), `ScopedPermissionBackend`. **Les 40 checks de conformité passent** (`uv run pytest`). Harnais : `tests/test_conformance.py` matérialise chaque cas JSON sur un modèle `Node` générique auto-référencé (levels partageant un modèle + `discriminator`).
- ⬜ `scoped_access/drf/` et `scoped_access/reauth/` : stubs TODO — écrire d'abord les cas de conformité manquants (write guard, ReAuth, `/me/access/`), doctrine spec-first.
- ⬜ Migrations Django du package (absentes : les tests passent par run_syncdb), modèles swappables, cache par requête, guide de migration DME/APSR.
- ⬜ Moteur + backend + tests (app de test interne avec hiérarchie factice).
- ⬜ Glue DRF, ReAuth.
- ⬜ Guide de migration DME (fusion des 6 FK `scope_*` → GFK) puis APSR (fusion "tenant par attribut user" → assignation ; remplacement du role-checking).
- Non décidé : nom définitif, org GitHub (PSETEAM vs perso), licence.

## Manière de travailler avec le propriétaire

- Discussion en **français** ; code, spec et docs publiques en **anglais** (projet open-source).
- **Discuter l'architecture avant d'implémenter** — ne pas foncer coder sur les points non tranchés.
- Git : intégration via Pull Request, pas de merge direct ; **pas de co-auteur IA dans les commits**.
- Serializers DRF : champs explicites, jamais `fields = "__all__"`. Penser index DB et `select_related`/`prefetch_related` systématiquement.
