# SPDX-FileCopyrightText: 2022-present Alexis Rodriguez <arodriguez99@protonmail.com>
#
# SPDX-License-Identifier: MIT

import rsa

class Signer:
    def __init__(self, priv_key) -> None:
        self.priv_key = priv_key
