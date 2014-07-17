function groups(callback, err, result) {
    var self = this;

    if (err) {
        self.log && self.log.trace('ldap authenticate: search error: %s', err);

        return callback(err);
    }

    var items = [];

    result.on('searchEntry', function (entry) {
        items.push(entry.object);
    });

    result.on('error', function (err) {
        self.log && self.log.trace(
            'ldap authenticate: search error event: %s', err);

        return callback('LDAP group not found: ' + self.opts.requireGroupDn);
    });

    result.on('end', function (result) {
        if (result.status !== 0) {
            var err = 'non-zero status from LDAP search: ' + result.status;
            self.log && self.log.trace('ldap authenticate: %s', err);
            return callback(err);
        }

        if (!items.length) {
            return callback('LDAP object is not group: ' + self.opts.requireGroupDn);
        }

        if (items.length > 1) {
            return callback(format(
                'unexpected number of matches (%s) for group %s',
                items.length, self.opts.requireGroupDn));
        }

        members = items[0].member || items[0].uniqueMember || '';

        if (members.indexOf(user.dn) === -1) {
            return callback('LDAP user ' + user.dn + ' is not member of group ' + self.opts.requireGroupDn);
        } else {
            return callback(null, user);
        }
    });
}

module.exports = groups;
