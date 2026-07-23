# TAP enclave measurement transparency log

Every deploy of the hosted TAP proxy records the identity of the exact code
that went live. The `cce_hostdata` column is the SHA-256 of the confidential
computing enforcement (CCE) policy — the SEV-SNP launch measurement that
Azure Key Vault's Secure Key Release policy pins. Microsoft's HSM releases
TAP's key-encryption key **only** to an enclave whose hardware attestation
carries one of these values; see the
[security model](https://docs.tap.human.tech/security) for the full chain.

## Verify the instance serving you

1. `curl https://app.tap.human.tech/health` → note `build.sha`.
2. Find that `git_sha` in the production table below.
3. That row's `cce_hostdata` is the only measurement the KEK release policy
   authorizes after each deploy's rollover prune — enforced by Microsoft
   Azure Attestation on hardware evidence, not by TAP.

Each row links to the GitHub Actions run that produced it, and the image is
cosign-signed by the pinned workflow identity in the `cosign_identity` field
of the raw log.

Raw, append-only data: [`production.jsonl`](production.jsonl) /
[`staging.jsonl`](staging.jsonl) (one JSON object per deploy, newest last).


## Production

| deployed_at (UTC) | git_sha | image digest (amd64) | CCE hostdata | run |
|---|---|---|---|---|
| 2026-07-22T20:55:22Z | `75210315a7e6` | `0b7cb59aac49f89f…` | `42c84d6e7e699e42ee5d61c0e37d4370b838b0a98deddb6365f22deeb589cf2d` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/29954047842) |
| 2026-07-14T00:11:59Z | `9830a020b1e2` | `a73ebc65c4a6321b…` | `3d17928cc1c940586692bf92d0a5e670269b0c14e10ebe255204ce6798b6e443` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28997892706) |
| 2026-07-09T05:28:56Z | `c688c290ad36` | `e9dc8e867cecd9c5…` | `6e0b27a85680f04ba2f4225bd717b828656160b59cc79156c232cf22d3da5338` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28995851479) |
| 2026-07-08T18:07:15Z | `28e31bf631ec` | `8c5f64ba2d89d32b…` | `3c096ce91570356c643e1de6d8719387aa6d1cee67d8ee63f94173ea33152c85` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28963750180) |
| 2026-07-08T05:01:07Z | `b435f65db6b1` | `0cc0a6967f5f7413…` | `8e722d797e150e887c9926cee5f8777d81c1f9b026c3a96f6114729cae9482c8` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28917268360) |
| 2026-07-01T11:37:21Z | `d0f64dfa43af` | `4ee6c40d9433d501…` | `8501430b3e8e14a0c91d15d78a7f8dd374d2c1447c083c60418aeacadd6bb14d` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28514140242) |
| 2026-06-24T16:12:39Z | `5c2b06cc50fe` | `5b2b152b920ca1e3…` | `6af07072a56bb21afdf85b65d32def51e54fcfbd1ebefb4eb48654180de2832f` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28069557413) |
| 2026-06-17T04:31:32Z | `7c3a3c335d27` | `cd74d1d32effff87…` | `a1c031c38b852ce2961eb11e55277a27685ecf0cf6dec1dfdd0a14b660bb71aa` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27665670241) |
| 2026-06-17T04:21:35Z | `09a6dccdc608` | `20ab4deba226e62f…` | `8f7b482bf1487315f8f45276c8f8ca60b73de926d78a8b57270015178d0f2afd` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27665354787) |
| 2026-06-10T20:31:34Z | `47e59d563678` | `0756666e5c9b33c2…` | `8fe7025979d7735dd3878edab738216eab0eda900558f98a3aaf6ed17da4fd52` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27272443540) |
| 2026-06-05T02:22:53Z | `2bab4199a3a8` | `a360ae49c4ea2238…` | `3adfd312fd78448a004ed100abf9dec0ff6b5e14a82cf46444a20535ecb0e670` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/26991302550) |
| 2026-06-05T01:56:15Z | `a3f24f484659` | `4ada70c5d8aeca27…` | `4b9aa00b1a19d783541c913ef89613e5dce981d27f72fdee5bd68e2f3ec7bc7a` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/26990462430) |
| 2026-06-03T22:52:16Z | `d09b92347bf5` | `dc7b22deccafc38e…` | `2d9ca586c901d929502c58a1ed3a0e07a6ab4fd35729d943b619ade25502161e` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/26918067341) |

## Staging

| deployed_at (UTC) | git_sha | image digest (amd64) | CCE hostdata | run |
|---|---|---|---|---|
| 2026-07-23T01:47:50Z | `4b5a40f5ffff` | `2f00a3bee928d9e3…` | `e547a2eb67fd983fc33b1ca0bd93c6065767e6ba33eadb36ec0e9f633e67c8d1` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/29972434978) |
| 2026-07-23T01:08:36Z | `a4dcdce12313` | `c33fbea8ddd43bf1…` | `57a5773eff9f81a5f150aeffd48f92c2d510614b672f4b8014dfdb9dd8687039` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/29970718536) |
| 2026-07-23T00:13:14Z | `ff1187c712fc` | `3dab4fab7dfddcde…` | `9a628774829339f603e8edfc02a0f5e07448604f817a38170a7a5ae26fe449a8` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/29968135469) |
| 2026-07-22T19:51:47Z | `99041d2f9b22` | `59abe5207b679d53…` | `d69d1b94b7426d0c47e67d5f8192ae69de2005070278c4dee71b81fb0afb2826` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/29952209093) |
| 2026-07-22T07:05:25Z | `3857debad71c` | `da523d9df70755cd…` | `d9f975df2fc96fcf81962f397986df4e3a68e2387232903a2b8a20791187230e` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/29898528418) |
| 2026-07-21T06:32:45Z | `d823d1091cd8` | `9ae06d214d02c7d3…` | `e367b7e61b44fcde31824e4bf4db1ac635d79a4a24829182a82f0b7fd4491231` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/29806454929) |
| 2026-07-09T06:07:36Z | `58dd851435a7` | `07ae6c9a9cfc1c7d…` | `609e8977fff13900d04515c509253aa123217d7947907d462477bb3b60c4e091` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28997606648) |
| 2026-07-09T05:16:07Z | `41d487f0cdbe` | `ec865e631c8b8a1e…` | `7eb9289450ff5250ce6b5f32ba9338d86d77123e4c46bcb9864e4dc38b06a6b9` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28995615008) |
| 2026-07-08T04:20:32Z | `24115c0ea9ef` | `d76a2df51102928b…` | `5f4e9e0ba1ce71e981d52de6fcf9984344212ad28f79f934efbd4d671af76fd5` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28916980378) |
| 2026-07-08T04:07:31Z | `5b431adcaa6c` | `0bf89510cce99fa4…` | `8019ae7fa35eecb2384bee75560c39edb7c1c3c475eec85c413e50109e4de869` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28916483002) |
| 2026-07-08T03:43:58Z | `3294c36ddd47` | `2ad6a3306c10a44f…` | `5486bbcc96dce4516905f9e1cbe7a144796b21e9a6dfbefef6c7effc19bb3812` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28915631259) |
| 2026-07-06T07:46:34Z | `398f631e455b` | `87f4a5ebd633616f…` | `ff74beb7afc3e174b431302611905a3b28f22b6c1e891f3b01d887e78160ef1b` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28775691121) |
| 2026-07-06T07:25:48Z | `c11fa24c9f7e` | `628faf1c26a39ef6…` | `b60e15c4884d61a213926d6b220ffa0d0a233faa094edffc911a8933efeaf2ca` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28774678774) |
| 2026-07-06T01:50:55Z | `ba374246e1f7` | `5c8b2fe62aedbab1…` | `b09d42db1b2d222790af8e967e0e6af3ce02486ead1fee460e0f166d291c8e96` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28762541522) |
| 2026-07-06T01:33:49Z | `aa8de2b48771` | `19078cfcabe406bc…` | `c34502464dd52a3e4dd8bbc6a8a659a3f2781a8d478c94cdda117113fdba5626` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28762048304) |
| 2026-07-02T20:42:05Z | `67ed263683e2` | `60a5bee717d0d66d…` | `9a40e68debd31f30ac49fe9d93298a0432f3a659d7965e0e091f14d8e6417901` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28619862768) |
| 2026-07-02T20:16:36Z | `16af0ffa3cc0` | `a3b41842e1367ded…` | `bed8863ab2bbdf7952c5adf78cf3588a3422a6ff8e01753b9fb5116784ff9506` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28618480336) |
| 2026-07-02T02:12:07Z | `acd165efa41b` | `58ca66e3cc00d464…` | `08ae19e5bbeb0166948b5c314ef224e9f9825955f6195cad1a37eec64f05a95e` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28560352083) |
| 2026-07-01T11:17:41Z | `272f4cf0819e` | `eb7f0e9a134bbdc4…` | `98bba4ae84922f8d20f6978db141b47ac48899af6b5a4c5073da49ba2e72dae3` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28513333798) |
| 2026-07-01T09:26:24Z | `d30112d58ee0` | `08d7dc1aff6100ff…` | `3c0af63faa9a86ca109c93b878d5fee371a57fa2855749c72d6bd698dc88fa28` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28507359068) |
| 2026-06-24T01:47:21Z | `6fd6ed12ea7f` | `e79a4cacd190fb28…` | `eeaddb74a409978c1dc3f9ac383d0fd94ed40c23c359aa6bea5c41fd8bd364b7` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28069403642) |
| 2026-06-23T22:58:27Z | `e2a87e5957ce` | `9d31a81c50c6bfff…` | `579c478855c7cfc61785aeb88484f588c83c386c7d53adebc5c8e29cd48164f9` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/28062487600) |
| 2026-06-19T04:39:54Z | `7efd8df71b41` | `640236475926ce60…` | `75e5d05ffb1afb6ee21c9e99e465cd090cb79df91bca8426dd8b2128dcb395a1` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27805569192) |
| 2026-06-19T04:10:33Z | `b3e8e9ef6710` | `ff10034d837fa2e6…` | `36b2de6542ad0e194ceb7a83b0568d3542a81c4b1cfcd063e44a603b1cc9ee03` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27804609970) |
| 2026-06-19T03:36:55Z | `7e508cc3b4d4` | `a02a3b20805f1756…` | `f1c21577fc75328f03b81544df242b9f39b30e5299fbe50e8147d2c71d5608e3` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27803609282) |
| 2026-06-18T05:14:32Z | `0c033e1f4de4` | `e311cfb32cd4a490…` | `987841587431e829023f0c9536f2ad433aeb7b40239a25e51119c79c5af3aaa7` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27738105085) |
| 2026-06-18T04:04:00Z | `54461e854a6c` | `c770c7def7498a4d…` | `174e7c2a4afca868aaad02f67ceb4db32930de74a4031a83372c4dd7bc731e12` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27735667278) |
| 2026-06-17T23:12:24Z | `7b522cc05239` | `55265c690d2e81ad…` | `faeb6d546e6009ce6ff2c1d5aab0336f31523d193063ed818593897e76b88e9e` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27725464652) |
| 2026-06-17T15:25:40Z | `18e9a8e2f37d` | `3b97d9c01156f16f…` | `79b2b7a33df60c890cb3076a97e3fb93694b254071bee0b214b86c1b4e0b1d75` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27699208624) |
| 2026-06-17T04:23:39Z | `df769f35bc89` | `1fa0676dc0427922…` | `f9ea2ae8209abaac95fcf5afbdb38e143b429ae3d385bf32dcc48cafa84fd8c9` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27665459826) |
| 2026-06-17T04:07:54Z | `e86128e4569b` | `0fac8c2efba68156…` | `b196275a97a5e47a6991513ccc791fd7921d7eb5a0a17de89c6b73ae565fd530` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27664896321) |
| 2026-06-17T03:43:35Z | `c4ef0fc42c53` | `2cedc9ed5c827ef2…` | `5f6162dfa1537cf82b5bb8be7f48b71f4553d8dc8319e419b7aaaadd6c929ecf` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27664083285) |
| 2026-06-12T00:37:22Z | `6a0952402c0f` | `20dacd8b3c29b592…` | `2ce5fc5e55a54bd45faaacea88b79cb50285d98324fbd5a592b0bc4355c68b77` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27386456397) |
| 2026-06-10T20:15:08Z | `47e59d563678` | `0756666e5c9b33c2…` | `98c8e46f85d09c6867d4f799d5120053668dd46532e8324c326c9fbde591a9f8` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/27303150110) |
| 2026-06-02T16:56:00Z | `1b06ced94fbf` | `7be91fddb32f4fec…` | `0cfcf313942b48b241c0053ad33da17c0f2a2a386e6bccde912cf8d64fb87a7f` | [run](https://github.com/holonym-foundation/agentsec/actions/runs/26834970922) |
