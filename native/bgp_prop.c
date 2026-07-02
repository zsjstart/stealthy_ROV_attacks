/* bgp_prop.c
 * Fast Gao-Rexford BGP announcement propagation for hijack-impact estimation,
 * with optional route leaks (valley-free violations).
 *
 * Route model. A single origin announces a prefix. Every AS selects a best route
 * by (tier, AS-path length): tier = customer(0) < peer(1) < provider(2), i.e.
 * customer-learned routes have the highest local-pref; ties broken by hop count.
 *
 * Export rules (Gao-Rexford):
 *   customer-learned route  -> re-export to providers, peers, customers
 *   peer/provider route     -> re-export to customers only
 *
 * Route leaks. A node flagged leak[u]=1 violates the rule: it re-exports EVERY
 * route it selects to ALL neighbours (providers, peers, customers), regardless of
 * how it learned the route. Leaks make the (tier,dist) key non-monotone along a
 * path, so the exact solve uses a label-correcting queue (SPFA). With no leakers
 * the key is monotone and a single bucketed-Dijkstra (Dial) sweep is exact and
 * faster; the caller picks the path.
 *
 * Build: gcc -O3 -march=native -shared -fPIC -Wall -o libbgp.so bgp_prop.c
 */
#include <stdlib.h>
#include <string.h>

#define T_CUST 0
#define T_PEER 1
#define T_PROV 2
#define NUM_TIERS 3
#define TIERMUL 1024              /* > any real AS-path length */
#define MAXKEY (NUM_TIERS * TIERMUL)
#define INF_KEY 0x3fffffff
#define MAX_DIST 63               /* drop routes longer than this (loop guard)  */

#define M_SUBPREFIX 0
#define M_PREFIX    1

#define S_SAFE      0
#define S_DIRECT    1
#define S_INDIRECT  2
#define S_NOROUTE   3
#define S_ORIGIN   -1

typedef struct {
    int n;
    const int *prov_off; const int *prov_nbr;   /* providers of u (u climbs up)   */
    const int *peer_off; const int *peer_nbr;    /* peers of u                     */
    const int *cust_off; const int *cust_nbr;    /* customers of u (u sends down)  */
    /* scratch */
    int *best_key;      /* [n]      */
    int *node_next;     /* [n]  Dial bucket list */
    int *bucket_head;   /* [MAXKEY] */
    int *queue;         /* [n+1] SPFA ring */
    unsigned char *inq; /* [n] */
    unsigned char *visited;  /* [n] */
    /* classify scratch */
    unsigned char *reaches;  /* [n] */
    unsigned char *cstate;   /* [n] 0 unknown,1 in-progress,2 done */
    int *cstack;             /* [n] */
} Graph;

static Graph G;

void bgp_init(int n,
              const int *prov_off, const int *prov_nbr,
              const int *peer_off, const int *peer_nbr,
              const int *cust_off, const int *cust_nbr) {
    G.n = n;
    G.prov_off = prov_off; G.prov_nbr = prov_nbr;
    G.peer_off = peer_off; G.peer_nbr = peer_nbr;
    G.cust_off = cust_off; G.cust_nbr = cust_nbr;
    G.best_key    = (int*)malloc(sizeof(int) * n);
    G.node_next   = (int*)malloc(sizeof(int) * n);
    G.bucket_head = (int*)malloc(sizeof(int) * MAXKEY);
    G.queue       = (int*)malloc(sizeof(int) * (n + 1));
    G.inq         = (unsigned char*)malloc(n);
    G.visited     = (unsigned char*)malloc(n);
    G.reaches     = (unsigned char*)malloc(n);
    G.cstate      = (unsigned char*)malloc(n);
    G.cstack      = (int*)malloc(sizeof(int) * n);
}

void bgp_free(void) {
    free(G.best_key); free(G.node_next); free(G.bucket_head);
    free(G.queue); free(G.inq); free(G.visited);
    free(G.reaches); free(G.cstate); free(G.cstack);
    memset(&G, 0, sizeof(G));
}

/* ---------- shared relax ---------- */
static inline int try_relax(int w, int tw, int nd, int u,
                            const unsigned char *is_rov, int rov_filter,
                            int *dist, int *tier, int *parent) {
    if (rov_filter && is_rov[w]) return 0;
    int key = tw * TIERMUL + nd;
    if (key < G.best_key[w]) {
        G.best_key[w] = key; dist[w] = nd; tier[w] = tw; parent[w] = u;
        return 1;
    }
    return 0;
}

/* ================= fast path: Dial's, NO leaks ================= */
void bgp_propagate(int origin, const unsigned char *is_rov, int rov_filter,
                   int *dist, int *tier, int *parent,
                   int *order, int *order_len) {
    const int n = G.n;
    for (int i = 0; i < n; ++i) {
        G.best_key[i] = INF_KEY; G.visited[i] = 0;
        dist[i] = -1; tier[i] = -1; parent[i] = -1;
    }
    for (int k = 0; k < MAXKEY; ++k) G.bucket_head[k] = -1;
    int ord = 0;

    G.best_key[origin] = 0; tier[origin] = T_CUST; dist[origin] = 0; parent[origin] = -1;
    G.node_next[origin] = -1; G.bucket_head[0] = origin;

    for (int k = 0; k < MAXKEY; ++k) {
        int v = G.bucket_head[k];
        while (v != -1) {
            int nxt = G.node_next[v];
            if (!G.visited[v] && G.best_key[v] == k) {
                G.visited[v] = 1;
                if (order) order[ord++] = v;
                int nd = dist[v] + 1;
                if (nd <= MAX_DIST) {
                    if (tier[v] == T_CUST) {
                        for (int e = G.prov_off[v]; e < G.prov_off[v+1]; ++e) {
                            int w = G.prov_nbr[e];
                            if (!G.visited[w] && try_relax(w, T_CUST, nd, v, is_rov, rov_filter, dist, tier, parent))
                                { G.node_next[w] = G.bucket_head[G.best_key[w]]; G.bucket_head[G.best_key[w]] = w; }
                        }
                        for (int e = G.peer_off[v]; e < G.peer_off[v+1]; ++e) {
                            int w = G.peer_nbr[e];
                            if (!G.visited[w] && try_relax(w, T_PEER, nd, v, is_rov, rov_filter, dist, tier, parent))
                                { G.node_next[w] = G.bucket_head[G.best_key[w]]; G.bucket_head[G.best_key[w]] = w; }
                        }
                        for (int e = G.cust_off[v]; e < G.cust_off[v+1]; ++e) {
                            int w = G.cust_nbr[e];
                            if (!G.visited[w] && try_relax(w, T_PROV, nd, v, is_rov, rov_filter, dist, tier, parent))
                                { G.node_next[w] = G.bucket_head[G.best_key[w]]; G.bucket_head[G.best_key[w]] = w; }
                        }
                    } else {
                        for (int e = G.cust_off[v]; e < G.cust_off[v+1]; ++e) {
                            int w = G.cust_nbr[e];
                            if (!G.visited[w] && try_relax(w, T_PROV, nd, v, is_rov, rov_filter, dist, tier, parent))
                                { G.node_next[w] = G.bucket_head[G.best_key[w]]; G.bucket_head[G.best_key[w]] = w; }
                        }
                    }
                }
            }
            v = nxt;
        }
    }
    if (order_len) *order_len = ord;
}

/* ================= leak path: SPFA label-correcting ================= */
void bgp_propagate_leak(int origin, const unsigned char *is_rov, int rov_filter,
                        const unsigned char *leak,
                        int *dist, int *tier, int *parent) {
    const int n = G.n;
    for (int i = 0; i < n; ++i) {
        G.best_key[i] = INF_KEY; G.inq[i] = 0;
        dist[i] = -1; tier[i] = -1; parent[i] = -1;
    }
    const int cap = n + 1;
    int head = 0, tail = 0;

    G.best_key[origin] = 0; tier[origin] = T_CUST; dist[origin] = 0; parent[origin] = -1;
    G.queue[tail++] = origin; G.inq[origin] = 1;

    while (head != tail) {
        int v = G.queue[head++]; if (head == cap) head = 0;
        G.inq[v] = 0;
        int nd = dist[v] + 1;
        if (nd > MAX_DIST) continue;
        int export_all = (tier[v] == T_CUST) || leak[v];
        if (export_all) {
            for (int e = G.prov_off[v]; e < G.prov_off[v+1]; ++e) {
                int w = G.prov_nbr[e];
                if (try_relax(w, T_CUST, nd, v, is_rov, rov_filter, dist, tier, parent) && !G.inq[w])
                    { G.queue[tail++] = w; if (tail == cap) tail = 0; G.inq[w] = 1; }
            }
            for (int e = G.peer_off[v]; e < G.peer_off[v+1]; ++e) {
                int w = G.peer_nbr[e];
                if (try_relax(w, T_PEER, nd, v, is_rov, rov_filter, dist, tier, parent) && !G.inq[w])
                    { G.queue[tail++] = w; if (tail == cap) tail = 0; G.inq[w] = 1; }
            }
            for (int e = G.cust_off[v]; e < G.cust_off[v+1]; ++e) {
                int w = G.cust_nbr[e];
                if (try_relax(w, T_PROV, nd, v, is_rov, rov_filter, dist, tier, parent) && !G.inq[w])
                    { G.queue[tail++] = w; if (tail == cap) tail = 0; G.inq[w] = 1; }
            }
        } else {
            for (int e = G.cust_off[v]; e < G.cust_off[v+1]; ++e) {
                int w = G.cust_nbr[e];
                if (try_relax(w, T_PROV, nd, v, is_rov, rov_filter, dist, tier, parent) && !G.inq[w])
                    { G.queue[tail++] = w; if (tail == cap) tail = 0; G.inq[w] = 1; }
            }
        }
    }
}

/* ================= classification (chain-based; works for both paths) ========= */
static inline int keyof(int d, int t) { return (d < 0) ? INF_KEY : t * TIERMUL + d; }

void bgp_classify(int attacker, int victim, int mode, int tie_to_victim,
                  const int *a_dist, const int *a_tier,
                  const int *v_dist, const int *v_tier, const int *v_parent,
                  int *status, long *counts) {
    const int n = G.n;

    /* 1) direct flag -> parked in status[] (1 direct, 0 not) */
    for (int v = 0; v < n; ++v) {
        if (v == attacker || v == victim) { status[v] = S_ORIGIN; continue; }
        int d;
        if (mode == M_SUBPREFIX) {
            d = (a_dist[v] != -1);
        } else {
            int ak = keyof(a_dist[v], a_tier[v]);
            int vk = keyof(v_dist[v], v_tier[v]);
            if      (ak < vk)  d = 1;
            else if (ak == vk) d = tie_to_victim ? 0 : 1;
            else               d = 0;
        }
        status[v] = d ? 1 : 0;
    }

    /* 2) does an AS's victim-bound traffic reach the attacker?  Walk the victim
     *    forwarding tree via v_parent with memoisation + cycle guard (leaks can
     *    reorder keys, so we cannot rely on a finalize order). */
    for (int v = 0; v < n; ++v) G.cstate[v] = 0;
    G.reaches[victim] = 0; G.cstate[victim] = 2;
    if (attacker >= 0) { G.reaches[attacker] = 1; G.cstate[attacker] = 2; }

    for (int s = 0; s < n; ++s) {
        if (G.cstate[s] == 2) continue;
        int top = 0, cur = s, result = 0;
        for (;;) {
            if (cur < 0)             { result = 0; break; }
            if (G.cstate[cur] == 2)  { result = G.reaches[cur]; break; }
            if (G.cstate[cur] == 1)  { result = 0; break; }          /* cycle */
            if (status[cur] == 1)    { G.reaches[cur] = 1; G.cstate[cur] = 2; result = 1; break; }
            G.cstate[cur] = 1; G.cstack[top++] = cur; cur = v_parent[cur];
        }
        while (top > 0) { int u = G.cstack[--top]; G.reaches[u] = (unsigned char)result; G.cstate[u] = 2; }
    }

    /* 3) finalise status + counts */
    long c_safe = 0, c_direct = 0, c_indirect = 0, c_noroute = 0;
    for (int v = 0; v < n; ++v) {
        if (v == attacker || v == victim) { status[v] = S_ORIGIN; continue; }
        if (status[v] == 1)       { status[v] = S_DIRECT;   c_direct++; }
        else if (G.reaches[v])    { status[v] = S_INDIRECT; c_indirect++; }
        else if (v_dist[v] == -1) { status[v] = S_NOROUTE;  c_noroute++; }
        else                      { status[v] = S_SAFE;     c_safe++; }
    }
    counts[0] = c_safe; counts[1] = c_direct; counts[2] = c_indirect; counts[3] = c_noroute;
}
