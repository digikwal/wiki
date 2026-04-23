<template lang='pug'>
  v-container(fluid, grid-list-lg)
    v-layout(row, wrap)
      v-flex(xs12)
        .admin-header
          img(src='/_assets/svg/icon-console.svg', alt='Developer Tools', style='width: 80px;')
          .admin-header-title
            .headline.primary--text Developer Tools
            .subtitle-1.grey--text Flags
          v-spacer
          v-btn(color='success', depressed, @click='save', large)
            v-icon(left) mdi-check
            span {{$t('common:actions.apply')}}

        v-card.mt-3(:class='$vuetify.theme.dark ? `grey darken-3-d5` : `white grey--text text--darken-3`')
          v-alert(color='red', :value='true', icon='mdi-alert', dark, prominent)
            span Do NOT enable these flags unless you know what you're doing!
            .caption Doing so may result in data loss or broken installation!
          v-card-text
            v-switch.mt-3(
              color='primary'
              hint='Enable stage-based LDAP diagnostics logs for login troubleshooting.'
              persistent-hint
              label='LDAP Debug'
              v-model='devFlags.ldapDebugEnabled'
              inset
            )
            v-select.mt-3(
              :items='ldapDebugModeItems'
              item-text='text'
              item-value='value'
              label='LDAP Debug Mode'
              hint='MASKED hides sensitive values and logs stable tokens. VERBOSE logs raw LDAP fields for deep troubleshooting.'
              persistent-hint
              v-model='devFlags.ldapDebugMode'
              :disabled='!devFlags.ldapDebugEnabled'
              outlined
              dense
            )
            v-alert.mt-3(
              v-if='devFlags.ldapDebugEnabled && devFlags.ldapDebugMode === `VERBOSE`'
              color='orange darken-2'
              dark
              dense
              icon='mdi-shield-alert'
            ) VERBOSE mode may log sensitive LDAP values. Use temporarily and rotate logs if needed.
            v-divider.mt-3
            v-switch.mt-3(
              color='red'
              hint='Log all queries made to the database to console.'
              persistent-hint
              label='SQL Query Logging'
              v-model='devFlags.sqlLog'
              inset
            )
</template>

<script>

import flagsQuery from 'gql/admin/dev/dev-query-flags.gql'
import flagsMutation from 'gql/admin/dev/dev-mutation-save-flags.gql'

export default {
  data() {
    return {
      devFlags: {
        ldapDebugEnabled: false,
        ldapDebugMode: 'MASKED',
        sqlLog: false
      },
      ldapDebugModeItems: [
        { text: 'MASKED (Default, safer)', value: 'MASKED' },
        { text: 'VERBOSE (Temporary troubleshooting)', value: 'VERBOSE' }
      ]
    }
  },
  methods: {
    async save() {
      try {
        await this.$apollo.mutate({
          mutation: flagsMutation,
          variables: {
            input: {
              ldapDebugEnabled: this.devFlags.ldapDebugEnabled,
              ldapDebugMode: this.devFlags.ldapDebugMode,
              sqlLog: this.devFlags.sqlLog
            }
          },
          watchLoading (isLoading) {
            this.$store.commit(`loading${isLoading ? 'Start' : 'Stop'}`, 'admin-dev-flags-update')
          }
        })
        this.$store.commit('showNotification', {
          style: 'success',
          message: 'Flags applied successfully.',
          icon: 'check'
        })
      } catch (err) {
        this.$store.commit('pushGraphError', err)
      }
    }
  },
  apollo: {
    devFlags: {
      query: flagsQuery,
      fetchPolicy: 'network-only',
      update: (data) => data.system.devFlags,
      watchLoading (isLoading) {
        this.$store.commit(`loading${isLoading ? 'Start' : 'Stop'}`, 'admin-dev-flags-refresh')
      }
    }
  }
}
</script>

<style lang='scss'>

</style>
